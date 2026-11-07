# pi-sandbox

[简体中文](README.md) | **English**

> A configurable permission approval pipeline and controlled-execution extension for the Pi coding agent.

## Overview

A Pi agent tool call can read or modify files, run shell commands, start child processes, access the network, or call external tools through MCP. Allowing or denying a call by tool name alone does not show its actual targets or guarantee that execution still matches what was reviewed.

`pi-sandbox` runs a configurable approval pipeline before a Pi tool call, then binds the approved scope to execution. Approval answers “may this operation continue?” The sandbox executor answers “what can the approved process actually access?” They work together so a model judgment or user confirmation is not treated as an operating-system boundary.

## Main features

### Configurable approval pipeline

The pipeline evaluates a tool call through ordered stages with distinct roles. Built-in stages cover structural analysis, caller and tool identity, rule evaluation, access assessment, and mode decisions. Bash, PowerShell, and external-command analysis can be enabled by configuration. LLM review, Decision review, and human approval can also be enabled as needed.

```text
Tool call
  → Structure and target analysis
  → Identity and rule checks
  → Filesystem, network, process, and other access assessment
  → Optional shell analysis and model review
  → Human review for requests that still need confirmation
  → allow / ask / deny result
```

#### Why the pipeline is needed

For example, one `bash` call can read a file, change configuration, start a process, and access the network. A single allow/deny decision based only on the tool name cannot describe each target or apply separate rules to file writes and network access.

The pipeline handles these questions in stages: it identifies the caller and tool, analyzes targets and applies policy, then sends only unresolved requests to a model or a person. Every node works from evidence captured for the same call. A later allow cannot override a denial, and a node error or timeout does not automatically allow execution.

#### Approval results

- `allow`: Continue to controlled execution within the approved scope.
- `ask`: Request additional review; in Pi, the human approval node handles unresolved requests.
- `deny`: Block the operation; later nodes cannot change it to allow.

#### Pipeline design goals

- **Handle different evidence separately.** Rule nodes apply explicit policy; analysis nodes identify paths, commands, and access targets; a model or person reviews requests that still need judgment.
- **Make decisions traceable.** Each node evaluates evidence for a specific call, making it possible to track which rule or review step affected the result.
- **Keep denials authoritative.** Later nodes cannot change an existing denial into an allow. A node failure or timeout does not automatically allow the call; unresolved requests remain pending or are denied.
- **Choose a mode for the task.** Use `/permission` to inspect or change the approval mode, and `/permission settings` to configure approval nodes and models.

### Sandbox-controlled execution

Approval does not grant unrestricted execution. `pi-sandbox` takes control of Pi built-in tools and managed MCP tools, then checks that the actual invocation still matches the reviewed identity, arguments, policy revision, and approved access scope. If the call changes or its authorization evidence becomes stale, the old approval is not reused.

Controlled execution can restrict:

- **Filesystem:** Grant read and write access to specific files or directories. A read grant cannot be widened into write access.
- **Processes:** Apply policy to child-process creation and enforce the corresponding isolation through the platform backend.
- **Network:** Built-in tools use the top-level network scope. `none` blocks network access; `allowlist` allows only entries in `allow` through a controlled egress proxy; `all` permits all network destinations. An omitted destination port allows HTTP 80 and HTTPS 443; use `port: "any"` for every port.
- **MCP:** MCP runs on the host by default while retaining approval and lifecycle management. When the experimental `experimental.mcpSandbox` switch is enabled, stdio and HTTP MCP services share the session sandbox and effective `execution.network` with built-in tools. Stdio services launch through the controlled backend, restricted destinations use temporary leases, and HTTP requests are checked against the same scope.
- **Codemode:** Nested tools inherit the outer call's approval without repeated review, but every nested execution still passes through controlled bindings and the sandbox.

Capabilities vary by platform and transport. If a backend is missing, cannot enforce a requested restriction, or cannot verify the execution scope, the operation is rejected instead of silently running without controls.

### Execution boundary

The sandbox applies to controlled built-in tool execution and to MCP calls only when the experimental MCP sandbox is explicitly enabled; it does not isolate the entire Pi process. MCP services running on the host by default, other extensions, and processes outside these controlled paths are not automatically sandboxed.

## Installation and configuration

After publication, install in Pi:

```sh
pi install npm:@sirzero/pi-sandbox
```

- Node.js `>=22.19.0`
- The Pi host dependencies must satisfy this package's declared `peerDependencies`
- Use `/permission` to change modes and `/permission settings` to configure approval nodes and models

The experimental MCP sandbox is disabled by default, so MCP services run directly on the host. To restore the sandbox path still under development, enable it explicitly in the global configuration:

```json
{
  "experimental": {
    "mcpSandbox": true
  }
}
```

## License

MIT. See [LICENSE](LICENSE).
