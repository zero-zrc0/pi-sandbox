use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::{BaseProcessUiConfig, ContainerPolicy, ExecutionRequest, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig, UiPolicy};
use mxc_sdk::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
use mxc_sdk::process_container_common::base_container_runner::BaseContainerRunner;
use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(args.len() >= 4 && args.len() % 2 == 0);
    let port: u16 = args[1].parse().unwrap();
    let root = std::env::var("SystemRoot").unwrap();
    let mode = std::env::var("MXC_PROBE_MODE").unwrap_or_default();
    let control = mode == "none" || mode == "all";
    let action = if mode == "all" { NetworkAction::Allow } else { NetworkAction::Deny };
    let mut script = String::new();
    for (index, target) in args.chunks_exact(2).enumerate() {
        let host = &target[0];
        let target_port: u16 = target[1].parse().unwrap();
        assert!(host.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':'));
        let family = if host.contains(':') { "InterNetworkV6" } else { "InterNetwork" };
        script.push_str(&format!("$c=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::{family}); try {{ $t=$c.ConnectAsync('{host}',{target_port}); if (!$t.Wait(3000) -or !$c.Connected) {{ throw 'failed' }}; Write-Output '{index}=connected' }} catch {{ Write-Output '{index}=blocked' }} finally {{ $c.Dispose() }};"));
    }
    if !control {
        script.push_str(&format!("$c=[Net.Sockets.TcpClient]::new(); try {{ $c.Connect('127.0.0.1',{port}); $s=$c.GetStream(); $s.ReadTimeout=3000; $b=[Text.Encoding]::ASCII.GetBytes('GET http://example.com/ HTTP/1.0'+[char]13+[char]10+[char]13+[char]10); $s.Write($b,0,$b.Length); $r=[byte[]]::new(128); $n=$s.Read($r,0,$r.Length); if ([Text.Encoding]::ASCII.GetString($r,0,$n) -notmatch '^HTTP/1.0 200') {{ throw 'bad response' }}; Write-Output 'proxy_http=ok' }} catch {{ Write-Output 'proxy_http=failed' }} finally {{ $c.Dispose() }};"));
    }
    let request = ExecutionRequest {
        script_code: format!("\"{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -Command \"{script}\""),
        working_directory: root.clone(),
        env: Some(vec![format!("SystemRoot={root}"), format!("SystemDrive={}", std::env::var("SystemDrive").unwrap()), format!("LOCALAPPDATA={}", std::env::var("LOCALAPPDATA").unwrap())]),
        policy: ContainerPolicy {
            readonly_paths: vec![root],
            capabilities: vec!["registryRead".into()],
            network_egress: Some(NetworkEgressPolicy { default: action, ..Default::default() }),
            network_ingress: Some(NetworkIngressPolicy { default: if mode == "none" { NetworkAction::Deny } else { NetworkAction::Allow }, host_loopback: if mode == "none" { NetworkAction::Deny } else { NetworkAction::Allow } }),
            network_specified: true,
            network_mode_specified: true,
            runtime_network_proxy_specified: !control,
            network_proxy: ProxyConfig { address: if control { None } else { Some(ProxyAddress::new("127.0.0.1".into(), port)) } },
            ui: UiPolicy { disable: false, ..Default::default() },
            base_process_ui: BaseProcessUiConfig { isolation: "desktop".into(), ..Default::default() },
            ..Default::default()
        },
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);
    let mut child = match BaseContainerRunner::new().spawn(&request, &mut logger, StdioMode::Pipes) {
        Ok(child) => child,
        Err(error) => { eprintln!("launch failed: {error:?}"); std::process::exit(125); }
    };
    let mut out = String::new();
    let mut err = String::new();
    child.take_stdout().unwrap().read_to_string(&mut out).unwrap();
    child.take_stderr().unwrap().read_to_string(&mut err).unwrap();
    let exit = child.wait().unwrap();
    print!("{out}");
    eprint!("{err}");
    std::process::exit(exit);
}
