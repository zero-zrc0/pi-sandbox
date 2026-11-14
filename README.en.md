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

Approval does not grant unrestricted execution. `pi-sandbox` takes control of Pi built-in tools, managed MCP tools, and sandbox tools declared in the rule table, then checks that the actual invocation still matches the reviewed identity, arguments, policy revision, and approved access scope. If the call changes or its authorization evidence becomes stale, the old approval is not reused.

Controlled execution can restrict:

- **Filesystem:** Grant read and write access to specific files or directories. A read grant cannot be widened into write access.
- **Processes:** Apply policy to child-process creation and enforce the corresponding isolation through the platform backend.
- **Network:** Built-in tools use the top-level network scope. `none` blocks network access; `allowlist` allows only entries in `allow` through a controlled egress proxy; `all` permits all network destinations. An omitted destination port allows HTTP 80 and HTTPS 443; use `port: "any"` for every port.
- **MCP:** Stdio and HTTP MCP use host transports. Tool calls still use approval, identity binding, and lifecycle management. The built-in tools' `execution.network` and sandbox restrictions do not apply to MCP services.
- **Codemode:** Nested tools inherit the outer call's approval without repeated review, but every nested execution still passes through controlled bindings and the sandbox.

Capabilities vary by platform and transport. If a backend is missing, cannot enforce a requested restriction, or cannot verify the execution scope, the operation is rejected instead of silently running without controls.

### Tool admission rules

`toolRules` is an admission rule table evaluated before approval: it looks at the tool name and call arguments and yields `allow`, `deny`, or `ask`. Rules are declared in the project configuration (`<project root>/.pi/extensions/pi-sandbox/config.json`) or the global configuration (`<agentDir>/extensions/pi-sandbox/config.json`; `agentDir` defaults to `~/.pi/agent`). Merged rules put project declarations first and global declarations after, each in declaration order.

Matching runs from highest to lowest priority:

1. Argument-level `deny`: `match.args` is declared and every entry matches.
2. Argument-level `allow`.
3. Tool-level `deny`: only `match.tool` is declared.
4. Tool-level `allow`.
5. No match → `ask`.

Within one priority, project rules come before global rules and the first matching rule in the same scope wins. Argument-level rules always outrank tool-level rules, even when a tool-level rule is declared first.

Wildcards apply to tool names and string argument values and always match the whole string:

- `*` matches zero or more characters but never `/`;
- `**` matches zero or more characters including `/`;
- `?` matches exactly one non-`/` character;
- There is no escape syntax: `\` matches a literal backslash. There are no regular expressions; write `*foo*` to match a substring.

`match.args` maps JSON Pointers to wildcards. When a declared argument is missing or not a string, that argument-level rule does not match; use a tool-level rule to admit such calls.

Decision behavior:

- `deny`: block the call. The reason contains `sandbox-denied-tool:<ruleId>` and a `permission:tool-rule` audit record is written.
- `allow`: skip the approval pipeline. Managed tools still run through controlled execution, and a rule with `sandbox` goes to the next section. Declared `profile` / `locations` validate file positions in the arguments and reject invalid input (`sandbox-tool-rule:<ruleId>:<reason>`). When an `allow` rule matches a host tool that `pi-sandbox` does not manage, the tool runs natively and is not covered by the sandbox, so do not use broad wildcards to allow unfamiliar tools.
- `ask`: continue into the existing approval pipeline. Only an explicit human choice of “Allow for this session” / “Deny for this session” is remembered; later calls with the same tool and arguments are not prompted again. Reviewer-model decisions are never remembered, and any argument change or a new session asks again.

`toolBindings` is deprecated. It is still accepted, but when no `toolRules` are in effect it is migrated into equivalent tool-level `allow` rules, with one `deprecated` configuration notice.

```json
{
  "toolRules": [
    { "id": "deny-mcp-shell", "match": { "tool": "mcp__*", "args": { "/command": "*rm -rf*" } }, "decision": "deny" },
    { "id": "deny-all-mcp", "match": { "tool": "mcp__*" }, "decision": "deny" },
    { "id": "allow-gitlog", "match": { "tool": "git_log" }, "decision": "allow",
      "sandbox": { "package": "@acme/pi-tool-gitlog", "entry": "./tool.js", "description": "Read git history." } }
  ]
}
```

In this example the dangerous `mcp__*` arguments and then all `mcp__*` calls are denied, and `git_log` is allowed as a sandbox tool. Tools that are undeclared or match no rule default to `ask`.

### Sandbox-hosted third-party tools

When an `allow` rule has a `sandbox` field, the rule also registers a pi tool for the model, named by `match.tool`, which must be concrete (no `*` or `?`). In the restricted modes each call runs in a one-shot worker inside the operating system sandbox; the worker writes its single result line and exits immediately instead of waiting for timers or listeners the module left behind. `full-access` has no sandbox to enter and runs the module in the host process (see below).

- Module location is either `sandbox.package` with an optional `sandbox.entry` (resolved from the declaring scope directory; `entry` is a package subpath resolved through the package's `exports`, so an unexported subpath fails resolution and the tool is skipped) or `sandbox.path` (relative to the session working directory — usually the project root where pi was started, not the git root — or absolute). `entry` is only valid with `package`. Declaration problems fall into two classes: a `sandbox` rule's `match.tool` must be a concrete name (no `*` or `?`), which the strict schema enforces at configuration load, so a wildcard sandbox declaration makes its configuration file fail validation; an unresolvable module or an unusable state directory is a runtime problem that is recorded as a diagnostic and only skips that tool.
- Metadata comes from the declaration: `sandbox.description` is the tool description, `sandbox.parameters` is a JSON Schema object for the arguments, and `sandbox.config` is arbitrary JSON passed to the module unchanged. The host never imports plugin code to read metadata.
- The module must load independently: a self-contained ESM module exporting `execute(args, ctx)`. `ctx` provides `cwd`, `stateDirectory`, `config`, `toolName`, and `signal`. An optional `probe()` runs once after loading to surface load problems early. Return `{ content: [...] }`, optionally with `details` / `isError`.
- In the restricted modes every call is a new process, so module-level memory does not survive between calls; `full-access` has no separate worker and loads the module in the host process (see below). Persist context to `ctx.stateDirectory`, the project's `.pi/sandbox-tools/<tool>/`. It is created automatically and is the implicit write grant the rule gives the tool (apart from `locations` explicitly declared as writable). It does not isolate tools from one another: the baseline of `default`/`auto-review` grants write access to the whole working directory, so another tool's `.pi/sandbox-tools/<other>/` remains writable outside `read-only`; use `read-only` or a tighter baseline for strict isolation.
- When one tool name is declared more than once, the first resolvable declaration wins (a declaration whose module cannot be resolved only produces a diagnostic and does not claim the name).

Errors and isolation:

- `execute` throws: the call returns a readable error result and the session continues.
- Timeout: only the restricted modes (`read-only`, `default`, `auto-review`) cap one call at 60 seconds. When that deadline expires the host terminates the worker and the error carries code `execution-timeout` with text containing `timed out after 60s` (other timeout reasons under the same code, such as a helper start timeout or a deadline that expires before the helper starts, keep their own text). The `full-access` host path has no such timeout.
- Rule removed or renamed: the registered tool is not removed from the model's tool list immediately, but calls are refused (`sandbox-tool-retired`). Re-declaring it as a sandbox tool revives it; converting the rule to a plain `allow` without `sandbox` keeps it refused (fail-closed). A same-name `deny` rule wins over that refusal and keeps its audit record.
- The module cannot load, does not export `execute`, or `probe()` fails: `sandbox-tool-not-loadable`.
- Access outside the granted scope: the operating-system sandbox error is returned verbatim, not rewritten as “tool not found”.

The execution path depends on the mode. In `read-only`, `default`, and `auto-review`, calls go through the controlled execution adapter, which starts the one-shot worker in the trusted helper (module directory readable, state directory writable). In `full-access` there is no operating-system sandbox to enter, so the host imports the module in its own process. In restricted modes the module's own files are readable only from the entry file's directory: keep multi-file modules beside the entry or bundle them into one file. A `dist/*.js` entry cannot read the package-root `package.json`, so Node may emit a `MODULE_TYPELESS_PACKAGE_JSON` warning on stderr; the result protocol is unaffected.

The rule table itself grants no operating-system permissions. `profile` / `locations` do more than produce approval facts and argument validation: for a sandbox rule, matching `locations` produce the path read/write authorization scopes in the execution plan. The plan is still carried out by the sandbox backend, and the operating system decides the real access.

### Execution boundary

The sandbox applies to controlled built-in tool execution, sandbox tools declared in the rule table, and the existing Codemode sandbox path; it does not isolate the entire Pi process. MCP services use host transports and are outside the built-in tool sandbox. Other extensions and processes outside these controlled paths are not automatically sandboxed.

## Installation and configuration

After publication, install in Pi:

```sh
pi install npm:@sirzero/pi-sandbox
```

- Node.js `>=22.19.0`
- The Pi host dependencies must satisfy this package's declared `peerDependencies`
- Use `/permission` to change modes and `/permission settings` to configure approval nodes and models

MCP servers use host stdio and HTTP transports. Their tool calls remain under approval and identity binding, but they do not inherit built-in filesystem or network restrictions.

## OS sandbox runtime

The OS sandbox is disabled by default. Installing or loading the extension and opening Settings do not download or start a native sandbox. Open `/permission settings` → `Experiments` and enable **OS Sandbox**. The extension then checks the fixed runtime directory and installs a matching resource. Automatic downloads accept only Release entries in the catalog shipped with the extension. Manually placed resources are trusted by the user; the extension still checks the fixed path, file layout, platform, architecture, protocol, and system capabilities.

```json
{
  "experimental": {
    "sandboxEnabled": true
  }
}
```

Place runtime files under `<plugin-root>/runtimes/<runtime-version>/<platform>-<arch>/`. Linux x64 and ARM64 runtime packages use musl static native files and include `bwrap` as a fallback. The helper prefers a compatible system `bwrap` found on `PATH` outside the workspace and falls back to the packaged binary when needed. The kernel must still allow user namespaces and provide the required Landlock and seccomp capabilities. If the extension catalog has no resource for the current platform, the status is unavailable and automatic download is not available.


## License

MIT. See [LICENSE](LICENSE).
