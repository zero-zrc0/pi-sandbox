use mxc_sdk::mxc_common::models::{
    ContainerPolicy, FallbackPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy,
    ProxyAddress, ProxyConfig,
};
use serde_json::Value;
use std::path::{Component, Path};

struct Grant<'a> {
    path: &'a str,
    access: &'a str,
    directory: bool,
}

fn key(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn valid_path(path: &str) -> bool {
    let path_value = Path::new(path);
    path_value.is_absolute()
        && !path.contains('\0')
        && !path_value
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

fn contains(grant: &Grant<'_>, target: &str, directory: bool) -> bool {
    let parent = key(grant.path);
    let child = key(target);
    parent == child && (grant.directory || !directory)
        || grant.directory
            && child
                .strip_prefix(&parent)
                .is_some_and(|suffix| suffix.starts_with('\\'))
}

pub fn compile_policy(plan: &Value) -> Result<ContainerPolicy, &'static str> {
    compile_policy_with_proxy(plan, None)
}

pub fn compile_policy_with_proxy(plan: &Value, proxy_port: Option<u16>) -> Result<ContainerPolicy, &'static str> {
    let network_action = match plan.pointer("/network/kind").and_then(Value::as_str) {
        Some("none") if proxy_port.is_none() => NetworkAction::Deny,
        Some("all") if proxy_port.is_none() => NetworkAction::Allow,
        Some("destinations") if proxy_port.is_some_and(|port| port != 0) => NetworkAction::Deny,
        _ => return Err("unsupported network policy"),
    };
    let grants = plan
        .get("filesystem")
        .and_then(Value::as_array)
        .ok_or("missing filesystem grants")?
        .iter()
        .map(|value| {
            let path = value
                .get("path")
                .and_then(Value::as_str)
                .ok_or("invalid grant path")?;
            if !valid_path(path) {
                return Err("invalid grant path");
            }
            let access = value
                .get("access")
                .and_then(Value::as_str)
                .ok_or("invalid grant access")?;
            if access != "read" && access != "write" && access != "deny-write" && access != "deny-access" {
                return Err("invalid grant access");
            }
            let directory = match value.get("granularity").and_then(Value::as_str) {
                Some("directory") => true,
                Some("file") => false,
                _ => return Err("invalid grant granularity"),
            };
            Ok(Grant {
                path,
                access,
                directory,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut policy = ContainerPolicy {
        fallback: FallbackPolicy {
            allow_dacl_mutation: false,
        },
        network_egress: Some(NetworkEgressPolicy {
            default: network_action,
            ..Default::default()
        }),
        network_ingress: Some(NetworkIngressPolicy {
            default: if proxy_port.is_some() { NetworkAction::Allow } else { network_action },
            host_loopback: if proxy_port.is_some() { NetworkAction::Allow } else { network_action },
        }),
        network_specified: true,
        network_mode_specified: true,
        runtime_network_proxy_specified: proxy_port.is_some(),
        network_proxy: ProxyConfig { address: proxy_port.map(|port| ProxyAddress::new("127.0.0.1".into(), port)) },
        ..Default::default()
    };
    for grant in grants.iter().filter(|grant| grant.access == "read" || grant.access == "write") {
        if grant.access == "write" {
            if !grants
                .iter()
                .any(|read| read.access == "read" && contains(read, grant.path, grant.directory))
            {
                return Err("write grant would add read access");
            }
            policy.readwrite_paths.push(grant.path.to_owned());
        } else {
            policy.readonly_paths.push(grant.path.to_owned());
        }
    }
    for restriction in grants.iter().filter(|grant| grant.access == "deny-write")
        .chain(grants.iter().filter(|grant| grant.access == "deny-access")) {
        if restriction.access == "deny-write" && !grants.iter().any(|grant| grant.access == "write" &&
            (contains(grant, restriction.path, restriction.directory) || contains(restriction, grant.path, grant.directory))) {
            continue;
        }
        policy.readwrite_paths.retain(|path| !contains(restriction, path, false));
        if restriction.access == "deny-access" {
            policy.readonly_paths.retain(|path| !contains(restriction, path, false));
            policy.denied_paths.push(restriction.path.to_owned());
        } else if grants.iter().any(|grant| grant.access == "read" && contains(grant, restriction.path, false)) {
            policy.readonly_paths.push(restriction.path.to_owned());
        } else {
            policy.denied_paths.push(restriction.path.to_owned());
        }
    }
    policy.readonly_paths.retain(|path| {
        !policy
            .readwrite_paths
            .iter()
            .any(|write| key(write) == key(path))
    });
    Ok(policy)
}
