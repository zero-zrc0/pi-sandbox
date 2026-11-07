use mxc_sdk::mxc_common::cmdline::{cmdline_from_argv_for_context, CommandLineContext};
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::{BaseProcessUiConfig, ExecutionRequest, UiPolicy};
use mxc_sdk::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
use mxc_sdk::process_container_common::base_container_runner::BaseContainerRunner;
use pi_sandbox_windows_mxc::{compile_policy, compile_policy_with_proxy};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::mem::{size_of, size_of_val};
use std::os::windows::fs::OpenOptionsExt;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const FILE_READ_DATA: u32 = 0x0001;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ_WRITE: u32 = 0x0003;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;

fn run_codemode_launcher(args: &[String]) -> Result<i32, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("missing Codemode Runtime command".into());
    }

    let mut command_line =
        cmdline_from_argv_for_context(args, CommandLineContext::WindowsCreateProcess)?
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
    let mut attribute_list_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attribute_list_size);
    }
    if attribute_list_size == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut attribute_storage = vec![0usize; attribute_list_size.div_ceil(size_of::<usize>())];
    let attribute_list =
        attribute_storage.as_mut_ptr().cast::<core::ffi::c_void>() as LPPROC_THREAD_ATTRIBUTE_LIST;
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_list_size) }
        == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    struct AttributeListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttributeListGuard {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _attribute_list_guard = AttributeListGuard(attribute_list);

    let standard_handles = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    if standard_handles
        .iter()
        .any(|handle| handle.is_null() || *handle == INVALID_HANDLE_VALUE)
    {
        return Err("Codemode Runtime standard pipe is unavailable".into());
    }
    if unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            standard_handles.as_ptr() as *const core::ffi::c_void,
            size_of_val(&standard_handles),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard_handles[0];
    startup.StartupInfo.hStdOutput = standard_handles[1];
    startup.StartupInfo.hStdError = standard_handles[2];
    startup.lpAttributeList = attribute_list;

    let mut process = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            null(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT,
            null(),
            null(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 {
        return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32).into());
    }

    let result = (|| -> Result<i32, io::Error> {
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        struct JobGuard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for JobGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _job_guard = JobGuard(job);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AssignProcessToJobObject(job, process.hProcess) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { ResumeThread(process.hThread) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if unsafe { WaitForSingleObject(process.hProcess, INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut exit_code = 0u32;
        if unsafe { GetExitCodeProcess(process.hProcess, &mut exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(exit_code as i32)
    })();
    if result.is_err() {
        unsafe {
            let _ = TerminateProcess(process.hProcess, 125);
            let _ = WaitForSingleObject(process.hProcess, INFINITE);
        }
    }
    unsafe {
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
    }
    result.map_err(Into::into)
}

fn path_key(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
    };
    path.trim_end_matches('\\').to_lowercase()
}

fn fixed_environment(values: &Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let entries = values.as_object().ok_or("missing environment")?;
    let mut output = Vec::new();
    let mut names = std::collections::HashSet::new();
    for (name, value) in entries {
        let value = value.as_str().ok_or("invalid environment")?;
        if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
            return Err("invalid environment".into());
        }
        let key = name.to_ascii_uppercase();
        if !names.insert(key.clone()) {
            return Err("duplicate environment name".into());
        }
        if key != "SYSTEMROOT" && key != "SYSTEMDRIVE" && key != "LOCALAPPDATA" {
            output.push(format!("{name}={value}"));
        }
    }
    for name in ["SystemRoot", "SystemDrive", "LOCALAPPDATA"] {
        let value = std::env::var(name)?;
        if value.is_empty() || value.contains('\0') {
            return Err("required system environment is unavailable".into());
        }
        output.push(format!("{name}={value}"));
    }
    Ok(output)
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin()
        .take(8 * 1024 * 1024)
        .read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    launch(request, false)
}

fn lock_path(path: &str) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn canonical_path(path: &str) -> io::Result<std::path::PathBuf> {
    let mut current = std::path::PathBuf::from(path);
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(&current) {
            Ok(mut resolved) => {
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(&current) {
                    Ok(_) => return Err(error),
                    Err(check) if check.kind() == std::io::ErrorKind::NotFound => {}
                    Err(check) => return Err(check),
                }
                let name = current.file_name().map(|value| value.to_os_string());
                match name {
                    Some(name) => missing.push(name),
                    None => return Err(error),
                }
                if !current.pop() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_canonical_path(path: &str) -> io::Result<bool> {
    let resolved = canonical_path(path)?;
    Ok(path_key(&resolved.to_string_lossy()) == path_key(path))
}

fn lock_grants(plan: &Value) -> Result<Vec<std::fs::File>, Box<dyn std::error::Error>> {
    let mut grant_handles = Vec::new();
    for grant in plan["filesystem"]
        .as_array()
        .ok_or("missing filesystem grants")?
    {
        let path = grant["path"].as_str().ok_or("invalid grant path")?;
        match lock_path(path) {
            Ok(handle) => {
                let metadata = handle.metadata()?;
                if !is_canonical_path(path)? {
                    return Err("grant path identity changed".into());
                }
                let expected = if metadata.is_dir() {
                    "directory"
                } else {
                    "file"
                };
                if grant["granularity"].as_str() != Some(expected) {
                    return Err("grant type mismatch".into());
                }
                grant_handles.push(handle);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("grant type unavailable".into()),
        }
    }
    Ok(grant_handles)
}

fn launch(request: Value, stdio: bool) -> Result<i32, Box<dyn std::error::Error>> {
    let codemode_runtime = match request.get("runtimeProfile") {
        None => false,
        Some(value) if value.as_str() == Some("codemode") => true,
        Some(_) => return Err("unsupported runtime profile".into()),
    };
    if codemode_runtime && !stdio {
        return Err("Codemode Runtime requires inherited stdio".into());
    }
    let plan = request.get("plan").ok_or("missing plan")?;
    if codemode_runtime && plan.pointer("/network/kind").and_then(Value::as_str) != Some("none") {
        return Err("Codemode Runtime network must be disabled".into());
    }
    if codemode_runtime
        && plan
            .get("environment")
            .and_then(Value::as_object)
            .ok_or("missing environment")?
            .keys()
            .any(|name| {
                name.eq_ignore_ascii_case("NODE_OPTIONS") || name.eq_ignore_ascii_case("NODE_PATH")
            })
    {
        return Err("Codemode Runtime injection environment is unsupported".into());
    }
    let proxy_port = match request.get("proxyPort") {
        None => None,
        Some(value) => Some(u16::try_from(value.as_u64().ok_or("invalid proxy port")?)?),
    };
    let mut policy = compile_policy_with_proxy(plan, proxy_port)?;
    if plan.pointer("/operation/kind").and_then(Value::as_str) == Some("builtin-tool")
        && plan["environment"]
            .as_object()
            .ok_or("missing environment")?
            .keys()
            .any(|name| {
                name.eq_ignore_ascii_case("NODE_OPTIONS") || name.eq_ignore_ascii_case("NODE_PATH")
            })
    {
        return Err("builtin runtime injection environment is unsupported".into());
    }
    let arbitrary_process = stdio
        || plan.pointer("/operation/kind").and_then(Value::as_str) == Some("shell")
        || (plan.pointer("/operation/kind").and_then(Value::as_str) == Some("builtin-tool")
            && matches!(
                plan.pointer("/operation/name").and_then(Value::as_str),
                Some("bash" | "powershell" | "grep" | "find")
            ));
    let mut protected_handles = Vec::new();
    if arbitrary_process {
        for path in plan["protectedPaths"]
            .as_array()
            .ok_or("missing protected paths")?
        {
            let path = path.as_str().ok_or("invalid protected path")?;
            match lock_path(path) {
                Ok(handle) => {
                    if !is_canonical_path(path)? {
                        return Err("protected path identity changed".into());
                    }
                    protected_handles.push(handle);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !is_canonical_path(path)? {
                        return Err("protected path identity changed".into());
                    }
                    policy
                        .readonly_paths
                        .retain(|candidate| path_key(candidate) != path_key(path));
                    if !policy
                        .denied_paths
                        .iter()
                        .any(|candidate| path_key(candidate) == path_key(path))
                    {
                        policy.denied_paths.push(path.to_owned());
                    }
                }
                Err(_) => return Err("required protected path is unavailable".into()),
            }
        }
    }
    let grant_handles = lock_grants(plan)?;
    if !policy.denied_paths.is_empty() && !BaseContainerRunner::supports_native_denied_paths() {
        return Err("native deny paths are unavailable".into());
    }
    let cwd = plan
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or("missing cwd")?;
    if !std::path::Path::new(cwd).is_absolute() {
        return Err("invalid cwd".into());
    }
    let args = request
        .get("argv")
        .and_then(Value::as_array)
        .ok_or("missing command")?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or("invalid command"))
        .collect::<Result<Vec<_>, _>>()?;
    if args.is_empty() {
        return Err("empty command".into());
    }
    let environment = fixed_environment(plan.get("environment").ok_or("missing environment")?)?;
    let system_root = std::env::var("SystemRoot")?;
    policy.readonly_paths.push(system_root);
    let volume_root = std::path::Path::new(cwd)
        .ancestors()
        .last()
        .ok_or("invalid cwd")?
        .to_string_lossy()
        .into_owned();
    if !codemode_runtime
        && !policy
            .readwrite_paths
            .iter()
            .chain(&policy.readonly_paths)
            .chain(&policy.denied_paths)
            .any(|path| path_key(path) == path_key(&volume_root))
    {
        policy.readonly_paths.push(volume_root);
    }
    policy.capabilities.push("registryRead".into());
    policy.ui = UiPolicy {
        disable: false,
        ..Default::default()
    };
    policy.base_process_ui = BaseProcessUiConfig {
        isolation: "desktop".into(),
        ..Default::default()
    };
    let is_cmd_shell = plan.pointer("/operation/kind").and_then(Value::as_str) == Some("shell")
        && args.len() == 5
        && std::path::Path::new(&args[0])
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("cmd.exe"))
        && args[1..4] == ["/d", "/s", "/c"];
    let args = if codemode_runtime {
        let launcher = std::env::current_exe()?;
        let mut launcher_args = vec![
            launcher.to_string_lossy().into_owned(),
            "codemode-launcher".into(),
        ];
        launcher_args.extend(args);
        launcher_args
    } else {
        args
    };
    let command_line = if is_cmd_shell {
        if args[4].contains('\0') {
            return Err("invalid command".into());
        }
        let prefix =
            cmdline_from_argv_for_context(&args[..4], CommandLineContext::WindowsCreateProcess)?;
        format!("{prefix} \"{}\"", args[4])
    } else {
        cmdline_from_argv_for_context(&args, CommandLineContext::WindowsCreateProcess)?
    };
    let native_request = ExecutionRequest {
        script_code: command_line,
        working_directory: cwd.to_owned(),
        env: Some(environment),
        policy,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);
    let mut child = BaseContainerRunner::new()
        .spawn(
            &native_request,
            &mut logger,
            if stdio {
                StdioMode::Inherit
            } else {
                StdioMode::Pipes
            },
        )
        .map_err(|_| {
            if codemode_runtime {
                let diagnostics = logger.get_buffer().to_string();
                if !diagnostics.is_empty() {
                    eprint!("{diagnostics}");
                }
            }
            if proxy_port.is_some() {
                "native proxy-only sandbox launch failed"
            } else {
                "native process launch failed"
            }
        })?;
    drop(grant_handles);
    drop(protected_handles);
    if stdio {
        return Ok(child.wait()?);
    }
    let mut stdout = child.take_stdout().ok_or("missing child stdout")?;
    let mut stderr = child.take_stderr().ok_or("missing child stderr")?;
    let mut stdin = child.take_stdin().ok_or("missing child stdin")?;
    let operation_input = request
        .get("input")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    print!("\x1ePI-MXC-READY\x1f");
    io::stdout().flush()?;
    let input_thread = std::thread::spawn(move || {
        let _ = stdin.write_all(operation_input.as_bytes());
    });
    let output_thread = std::thread::spawn(move || {
        let _ = io::copy(&mut stdout, &mut io::stdout());
    });
    let error_thread = std::thread::spawn(move || {
        let _ = io::copy(&mut stderr, &mut io::stderr());
    });
    let exit = child.wait()?;
    let _ = input_thread.join();
    let _ = output_thread.join();
    let _ = error_thread.join();
    Ok(exit)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("codemode-launcher") {
        let arguments = std::env::args().skip(2).collect::<Vec<_>>();
        match run_codemode_launcher(&arguments) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("codemode-launcher-failed: {error}");
                std::process::exit(125);
            }
        }
    }
    if std::env::args().nth(1).as_deref() == Some("stdio") {
        let result = std::env::var("PI_MXC_REQUEST")
            .map_err(|_| "missing stdio request".into())
            .and_then(|value| {
                if value.len() > 24_000 {
                    return Err("stdio request is too large".into());
                }
                let request = serde_json::from_str(&value)?;
                launch(request, true)
            });
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("sandbox-setup-failed: {error}");
                std::process::exit(125);
            }
        }
    }
    if std::env::args().nth(1).as_deref() == Some("probe") {
        let root = match std::env::var("SystemRoot") {
            Ok(value) => value,
            Err(_) => std::process::exit(1),
        };
        let mut policy = match compile_policy(&serde_json::json!({
            "filesystem": [{"path": root, "access": "read", "granularity": "directory"}],
            "protectedPaths": [], "network": {"kind": "none"}
        })) {
            Ok(policy) => policy,
            Err(_) => std::process::exit(1),
        };
        policy.capabilities.push("registryRead".into());
        let request = ExecutionRequest {
            script_code: format!("\"{root}\\System32\\cmd.exe\" /d /c exit 0"),
            working_directory: root,
            env: fixed_environment(&serde_json::json!({})).ok(),
            policy,
            ..Default::default()
        };
        if request.env.is_none() {
            std::process::exit(1);
        }
        let mut logger = Logger::new(Mode::Buffer);
        let available = BaseContainerRunner::new()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .ok()
            .and_then(|mut process| process.wait().ok())
            == Some(0);
        let enumerate = BaseContainerRunner::supports_enumerate_paths();
        let deny = BaseContainerRunner::supports_native_denied_paths();
        println!("{{\"available\":{available},\"enumerate\":{enumerate},\"deny\":{deny}}}");
        if !available {
            std::process::exit(1);
        }
        return;
    }
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("sandbox-setup-failed: {error}");
            std::process::exit(125);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lock_grants;

    #[test]
    fn grant_handles_prevent_replacement_until_released() {
        let root = std::env::temp_dir().join(format!(
            "mxc-grant-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("file");
        let directory = root.join("directory");
        std::fs::write(&file, b"original").unwrap();
        std::fs::create_dir(&directory).unwrap();
        let plan = serde_json::json!({ "filesystem": [
            { "path": file, "granularity": "file" },
            { "path": directory, "granularity": "directory" }
        ] });
        let handles = lock_grants(&plan).unwrap();
        let moved_file = root.join("moved-file");
        let moved_directory = root.join("moved-directory");
        assert!(std::fs::rename(&file, &moved_file).is_err());
        assert!(std::fs::rename(&directory, &moved_directory).is_err());
        let moved_root = root.with_extension("moved");
        assert!(std::fs::rename(&root, &moved_root).is_err());
        drop(handles);
        std::fs::rename(&file, &moved_file).unwrap();
        std::fs::rename(&directory, &moved_directory).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
