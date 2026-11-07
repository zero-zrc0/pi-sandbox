use mxc_sdk::mxc_common::models::NetworkAction;
use pi_sandbox_windows_mxc::{compile_policy, compile_policy_with_proxy};
use serde_json::json;

#[test]
fn translates_read_write_roots_and_protects_control_paths() {
    let plan = json!({
        "filesystem": [
            {"path": "C:\\workspace", "access": "read", "granularity": "directory"},
            {"path": "C:\\workspace", "access": "write", "granularity": "directory"}
        ],
        "protectedPaths": ["C:\\workspace\\.git"],
        "network": {"kind": "none"}
    });
    let policy = compile_policy(&plan).expect("supported policy");
    assert_eq!(policy.readwrite_paths, ["C:\\workspace"]);
    assert!(policy
        .readonly_paths
        .contains(&"C:\\workspace\\.git".to_string()));
    assert!(policy.denied_paths.is_empty());
    assert!(policy.network_specified);
    assert!(!policy.fallback.allow_dacl_mutation);
}

#[test]
fn rejects_write_grants_that_would_add_unapproved_read_access() {
    let plan = json!({
        "filesystem": [{"path": "C:\\workspace", "access": "write", "granularity": "directory"}],
        "protectedPaths": [],
        "network": {"kind": "none"}
    });
    assert!(compile_policy(&plan).is_err());
}

#[test]
fn rejects_network_profiles_that_the_backend_does_not_enforce() {
    for kind in ["destinations", "unknown"] {
        let plan = json!({"filesystem": [], "protectedPaths": [], "network": {"kind": kind}});
        assert!(compile_policy(&plan).is_err());
    }
}

#[test]
fn requires_a_trusted_port_for_proxy_only_policy() {
    let plan = json!({"filesystem": [], "protectedPaths": [], "network": {"kind": "destinations"}});
    assert!(compile_policy_with_proxy(&plan, None).is_err());
    assert!(compile_policy_with_proxy(&plan, Some(0)).is_err());
    let policy = compile_policy_with_proxy(&plan, Some(31415)).unwrap();
    assert_eq!(policy.network_egress.unwrap().default, NetworkAction::Deny);
    let ingress = policy.network_ingress.unwrap();
    assert_eq!(ingress.default, NetworkAction::Allow);
    assert_eq!(ingress.host_loopback, NetworkAction::Allow);
    assert!(policy.runtime_network_proxy_specified);
    let address = policy.network_proxy.address.unwrap();
    assert_eq!(address.host(), "127.0.0.1");
    assert_eq!(address.port, 31415);
    for kind in ["none", "all"] {
        let plan = json!({"filesystem": [], "protectedPaths": [], "network": {"kind": kind}});
        assert!(compile_policy_with_proxy(&plan, Some(31415)).is_err());
    }
}

#[test]
fn translates_none_and_all_network_scopes_without_changing_file_permissions() {
    for (kind, expected) in [("none", NetworkAction::Deny), ("all", NetworkAction::Allow)] {
        let policy = compile_policy(&json!({
            "filesystem": [{"path": "C:\\workspace", "access": "read", "granularity": "directory"}],
            "protectedPaths": ["C:\\workspace\\.git"], "network": {"kind": kind}
        }))
        .expect("supported network scope");
        assert_eq!(policy.network_egress.unwrap().default, expected);
        let ingress = policy.network_ingress.unwrap();
        assert_eq!(ingress.default, expected);
        assert_eq!(ingress.host_loopback, expected);
        assert_eq!(
            policy.readonly_paths,
            ["C:\\workspace", "C:\\workspace\\.git"]
        );
        assert!(policy.readwrite_paths.is_empty());
    }
}

#[test]
fn rejects_a_write_grant_equal_to_a_protected_path() {
    let plan = json!({
        "filesystem": [
            {"path": "C:\\workspace\\.git", "access": "read", "granularity": "directory"},
            {"path": "C:\\workspace\\.git", "access": "write", "granularity": "directory"}
        ],
        "protectedPaths": ["C:\\workspace\\.git"],
        "network": {"kind": "none"}
    });
    assert!(compile_policy(&plan).is_err());
}

#[test]
fn rejects_write_grants_beneath_protected_paths() {
    for (path, granularity) in [
        ("C:\\workspace\\.git\\config", "file"),
        ("C:\\workspace\\.GIT\\hooks", "directory"),
    ] {
        let plan = json!({
            "filesystem": [
                {"path": "C:\\workspace", "access": "read", "granularity": "directory"},
                {"path": path, "access": "write", "granularity": granularity}
            ],
            "protectedPaths": ["C:\\workspace\\.git"],
            "network": {"kind": "none"}
        });
        assert!(compile_policy(&plan).is_err(), "write grant: {path}");
    }
}

#[test]
fn does_not_confuse_a_sibling_with_a_protected_path() {
    let plan = json!({
        "filesystem": [
            {"path": "C:\\workspace", "access": "read", "granularity": "directory"},
            {"path": "C:\\workspace\\.github", "access": "write", "granularity": "directory"}
        ],
        "protectedPaths": ["C:\\workspace\\.git"],
        "network": {"kind": "none"}
    });
    assert!(compile_policy(&plan).is_ok());
}

#[test]
fn rejects_paths_with_parent_traversal() {
    let plan = json!({
        "filesystem": [{"path": "C:\\workspace\\..\\secret", "access": "read", "granularity": "directory"}],
        "protectedPaths": [],
        "network": {"kind": "none"}
    });
    assert!(compile_policy(&plan).is_err());
}
