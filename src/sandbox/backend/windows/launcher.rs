#![cfg(windows)]
use std::{ffi::{c_void, OsStr}, io, mem::{size_of, zeroed}, os::windows::ffi::OsStrExt, ptr::{null, null_mut}};

type Handle = *mut c_void;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[repr(C)]
struct StartupInfo {
    cb: u32, reserved: *mut u16, desktop: *mut u16, title: *mut u16,
    x: u32, y: u32, width: u32, height: u32, chars_x: u32, chars_y: u32,
    fill: u32, flags: u32, show: u16, reserved_bytes: u16, reserved_data: *mut u8,
    stdin: Handle, stdout: Handle, stderr: Handle,
}
#[repr(C)]
struct StartupInfoEx { startup: StartupInfo, attributes: Handle }
#[repr(C)]
struct ProcessInfo { process: Handle, thread: Handle, pid: u32, tid: u32 }
#[repr(C)]
struct SecurityCapabilities { sid: Handle, capabilities: Handle, count: u32, reserved: u32 }
#[repr(C)]
struct BasicLimits { process_time: i64, job_time: i64, flags: u32, min_working: usize, max_working: usize,
    active_processes: u32, affinity: usize, priority: u32, scheduling: u32 }
#[repr(C)]
struct ExtendedLimits { basic: BasicLimits, io: [u64; 6], process_memory: usize, job_memory: usize,
    peak_process_memory: usize, peak_job_memory: usize }
#[repr(C)]
struct Accounting { user_time: i64, kernel_time: i64, period_user: i64, period_kernel: i64,
    faults: u32, total: u32, active: u32, terminated: u32 }

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: Handle, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: u32, information: Handle, length: u32) -> i32;
    fn QueryInformationJobObject(job: Handle, class: u32, information: Handle, length: u32, returned: *mut u32) -> i32;
    fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
    fn InitializeProcThreadAttributeList(list: Handle, count: u32, flags: u32, bytes: *mut usize) -> i32;
    fn UpdateProcThreadAttribute(list: Handle, flags: u32, attribute: usize, value: Handle, size: usize,
        previous: Handle, returned: *mut usize) -> i32;
    fn DeleteProcThreadAttributeList(list: Handle);
    fn CreateProcessW(application: *const u16, command: *mut u16, process_attributes: Handle,
        thread_attributes: Handle, inherit: i32, flags: u32, environment: Handle, cwd: *const u16,
        startup: *mut StartupInfo, information: *mut ProcessInfo) -> i32;
    fn ResumeThread(thread: Handle) -> u32;
    fn GetCurrentProcess() -> Handle;
    fn GetStdHandle(which: u32) -> Handle;
    fn DuplicateHandle(source_process: Handle, source: Handle, target_process: Handle,
        target: *mut Handle, access: u32, inherit: i32, options: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn WaitForSingleObject(handle: Handle, timeout: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
}
#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(name: *const u16, display: *const u16, description: *const u16,
        capabilities: Handle, count: u32, sid: *mut Handle) -> i32;
    fn DeriveAppContainerSidFromAppContainerName(name: *const u16, sid: *mut Handle) -> i32;
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn FreeSid(sid: Handle) -> Handle;
    fn ConvertSidToStringSidW(sid: Handle, string: *mut *mut u16) -> i32;
}

struct OwnedHandle(Handle);
impl Drop for OwnedHandle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
struct Sid(Handle);
impl Drop for Sid { fn drop(&mut self) { unsafe { FreeSid(self.0); } } }
struct Attributes { memory: Vec<usize>, initialized: bool }
impl Drop for Attributes { fn drop(&mut self) { if self.initialized { unsafe { DeleteProcThreadAttributeList(self.memory.as_mut_ptr().cast()); } } } }

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> { value.as_ref().encode_wide().chain(Some(0)).collect() }
fn check(ok: i32) -> Result<()> { if ok == 0 { Err(io::Error::last_os_error().into()) } else { Ok(()) } }
fn profile(name: &str) -> Result<Sid> {
    if !name.starts_with("pi-sandbox-") || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        return Err("profile must be a pi-sandbox- prefixed identifier".into());
    }
    let name = wide(name); let mut sid = null_mut();
    let result = unsafe { CreateAppContainerProfile(name.as_ptr(), name.as_ptr(), name.as_ptr(), null_mut(), 0, &mut sid) };
    if result == 0x800700B7u32 as i32 {
        let derived = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if derived < 0 { return Err(format!("derive AppContainer failed: {derived:#x}").into()); }
    } else if result < 0 { return Err(format!("create AppContainer failed: {result:#x}").into()); }
    Ok(Sid(sid))
}

fn quote(value: &str) -> String {
    let mut result = String::from("\""); let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' { slashes += 1; continue; }
        if character == '"' { result.push_str(&"\\".repeat(slashes * 2 + 1)); }
        else { result.push_str(&"\\".repeat(slashes)); }
        result.push(character); slashes = 0;
    }
    result.push_str(&"\\".repeat(slashes * 2)); result.push('"'); result
}

fn run(args: &[String]) -> Result<u32> {
    if args.len() < 3 { return Err("run requires profile, cwd, and absolute executable".into()); }
    let sid = profile(&args[0])?;
    if !std::path::Path::new(&args[2]).is_absolute() { return Err("executable must be absolute".into()); }
    let job = OwnedHandle(unsafe { CreateJobObjectW(null_mut(), null()) });
    if job.0.is_null() { return Err(io::Error::last_os_error().into()); }
    let mut limits: ExtendedLimits = unsafe { zeroed() };
    limits.basic.flags = 0x2000; // Closing the last job handle kills every descendant.
    unsafe { check(SetInformationJobObject(job.0, 9, (&mut limits as *mut ExtendedLimits).cast(), size_of::<ExtendedLimits>() as u32))?; }
    let mut bytes = 0;
    unsafe { InitializeProcThreadAttributeList(null_mut(), 3, 0, &mut bytes); }
    let mut attributes = Attributes { memory: vec![0; bytes.div_ceil(size_of::<usize>())], initialized: false };
    let list = attributes.memory.as_mut_ptr().cast();
    unsafe { check(InitializeProcThreadAttributeList(list, 3, 0, &mut bytes))?; }
    attributes.initialized = true;
    let mut security = SecurityCapabilities { sid: sid.0, capabilities: null_mut(), count: 0, reserved: 0 };
    let process = unsafe { GetCurrentProcess() };
    let mut handles = Vec::new();
    for which in [-10i32, -11, -12] {
        let mut duplicate = null_mut();
        unsafe { check(DuplicateHandle(process, GetStdHandle(which as u32), process, &mut duplicate, 0, 1, 2))?; }
        handles.push(OwnedHandle(duplicate));
    }
    let mut inherited = [handles[0].0, handles[1].0, handles[2].0];
    let mut job_list = [job.0];
    unsafe {
        check(UpdateProcThreadAttribute(list, 0, 0x20009, (&mut security as *mut SecurityCapabilities).cast(), size_of::<SecurityCapabilities>(), null_mut(), null_mut()))?;
        check(UpdateProcThreadAttribute(list, 0, 0x20002, inherited.as_mut_ptr().cast(), size_of_val(&inherited), null_mut(), null_mut()))?;
        // Assignment happens during CreateProcess, so a launcher crash cannot
        // strand a suspended child between process creation and job assignment.
        check(UpdateProcThreadAttribute(list, 0, 0x2000D, job_list.as_mut_ptr().cast(), size_of_val(&job_list), null_mut(), null_mut()))?;
    }
    let mut startup: StartupInfoEx = unsafe { zeroed() };
    startup.startup.cb = size_of::<StartupInfoEx>() as u32;
    startup.startup.flags = 0x100;
    startup.startup.stdin = inherited[0]; startup.startup.stdout = inherited[1]; startup.startup.stderr = inherited[2];
    startup.attributes = list;
    let executable = wide(&args[2]); let cwd = wide(&args[1]);
    let mut command = wide(args[2..].iter().map(|value| quote(value)).collect::<Vec<_>>().join(" "));
    // Windows needs its system directory to create an AppContainer process.
    // Read it from the OS; controller credentials are never inherited.
    let mut windows_directory = [0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(windows_directory.as_mut_ptr(), windows_directory.len() as u32) } as usize;
    if length == 0 || length >= windows_directory.len() { return Err(io::Error::last_os_error().into()); }
    let windows_directory = String::from_utf16(&windows_directory[..length])?;
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is required to resolve the AppContainer profile")?;
    let mut environment = wide(format!("LOCALAPPDATA={}\0SystemRoot={windows_directory}\0windir={windows_directory}\0", local_app_data.to_string_lossy()));
    let mut information: ProcessInfo = unsafe { zeroed() };
    unsafe { check(CreateProcessW(executable.as_ptr(), command.as_mut_ptr(), null_mut(), null_mut(), 1,
        0x80000 | 0x400 | 4 | 0x08000000, environment.as_mut_ptr().cast(), cwd.as_ptr(),
        &mut startup.startup, &mut information))?; }
    let child = OwnedHandle(information.process); let thread = OwnedHandle(information.thread);
    if unsafe { ResumeThread(thread.0) } == u32::MAX { return Err(io::Error::last_os_error().into()); }
    if unsafe { WaitForSingleObject(child.0, u32::MAX) } != 0 { return Err(io::Error::last_os_error().into()); }
    let mut exit_code = 0;
    unsafe {
        check(GetExitCodeProcess(child.0, &mut exit_code))?;
        check(TerminateJobObject(job.0, 1))?;
    }
    for _ in 0..100 {
        let mut accounting: Accounting = unsafe { zeroed() };
        unsafe { check(QueryInformationJobObject(job.0, 1, (&mut accounting as *mut Accounting).cast(), size_of::<Accounting>() as u32, null_mut()))?; }
        if accounting.active == 0 { return Ok(exit_code); }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("process tree did not exit within 5 seconds".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<u32> = (|| match args.first().map(String::as_str) {
        Some("profile") if args.len() == 2 => {
            let sid = profile(&args[1])?; let mut string = null_mut();
            unsafe { check(ConvertSidToStringSidW(sid.0, &mut string))?; }
            let mut length = 0; unsafe { while *string.add(length) != 0 { length += 1; } }
            println!("{}", String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(string, length) }));
            unsafe { LocalFree(string.cast()); } Ok(0)
        }
        Some("remove-profile") if args.len() == 2 && args[1].starts_with("pi-sandbox-") => {
            let result = unsafe { DeleteAppContainerProfile(wide(&args[1]).as_ptr()) };
            if result < 0 { Err(format!("delete AppContainer failed: {result:#x}").into()) } else { Ok(0) }
        }
        Some("run") => run(&args[1..]),
        _ => Err("usage: launcher profile NAME | remove-profile NAME | run NAME CWD EXE [ARGS]".into()),
    })();
    match result { Ok(code) => std::process::exit(code as i32), Err(error) => { eprintln!("sandbox-setup-failed: {error}"); std::process::exit(125); } }
}
