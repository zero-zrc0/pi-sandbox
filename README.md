# pi-sandbox
拦截 Pi coding agent 的工具调用，按策略审批，并把批准范围绑定到受控执行。

`pi install npm:@sirzero/pi-sandbox`

## 它解决什么问题

Pi 工具调用可能同时读写文件、启动进程或联网，按工具名审批无法区分具体目标。pi-sandbox 在执行前分析调用并运行审批链，把批准范围绑定到实际执行。

## Quick start

运行环境：Node.js `>=22.19.0`；Pi 宿主需满足 `@earendil-works/pi-ai >=1.4.0`、`@earendil-works/pi-coding-agent >=1.5.0`、`@earendil-works/pi-tui >=1.0.0`。

在已运行的 Pi 宿主中执行：

~~~sh
pi install npm:@sirzero/pi-sandbox
~~~

Pi TUI 中输入 `/permission`；没有浏览器访问地址，也无需数据库、Redis 或初始化数据。

### 执行边界

受控执行支持 Linux 和 Windows；其他平台为 `unsupported-platform`。沙箱只约束被接管工具和规则声明工具，不隔离整个 Pi 进程；MCP 经宿主 transport 运行，不受内置工具沙箱的文件系统和网络约束。

## 最小示例

在 Pi 输入：

~~~text
/permission
~~~

选择 `default` 后，Pi 预期提示：`Approval mode set to "default" for the current session only.`；该选择只作用于当前会话。

## 配置项

JSON 配置存放在项目级 `.pi/extensions/pi-sandbox/config.json` 或全局 `<agentDir>/extensions/pi-sandbox/config.json`。默认 `agentDir` 为 `~/.pi/agent`。

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `PI_CODEMODE_MAX_WORKERS` | 否 | `2` | 正整数；大于 `8` 时按 `8` 处理；未设置或值无效时使用 `2`。 |

完整配置字段和默认值见 [JSON Schema](schemas/permissions.schema.json)。

## OS 沙箱运行文件

OS 沙箱默认关闭。安装、加载扩展和打开设置不会下载或启动原生沙箱。使用 `/permission settings` → `Experiments` 开启 **OS Sandbox** 后，扩展才会检查固定运行目录并选择扩展包内可信目录中的最新兼容 Release。缺少运行时会先询问是否下载；已有运行时的更新会在验证和探测暂存文件后替换。手动放入的资源仍检查固定目录、文件结构、平台、架构、协议和系统能力；可信目录有兼容目标时，还须匹配目标文件哈希才会复用。

```json
{
  "experimental": {
    "sandboxEnabled": true
  }
}
```

运行文件与全局审批链配置共用目录：`<agentDir>/extensions/pi-sandbox/runtimes/<platform>-<arch>/`。每个平台架构只保留一个运行目录，运行时版本记录在 `runtime.json`。默认 `agentDir` 为 `~/.pi/agent`；设置 `PI_CODING_AGENT_DIR` 后使用自定义 agent 目录。手动下载的运行包也放在此处，不放进 npm 包目录或项目配置目录。Sandbox 启用时会按扩展随附的可信目录检查兼容版本；缺少运行时仍需确认下载，已安装运行时的更新会在暂存目录验证并探测后替换。若本地没有兼容运行时，且可信目录也没有兼容条目，状态会显示 unavailable。Linux x64 和 ARM64 运行包使用 musl 静态原生文件，并自带 `bwrap` 作为回退；助手优先使用 `PATH` 中位于工作区外、通过所需参数和 user namespace 探测的系统 `bwrap`，不兼容时再用随包版本。内核仍须允许 user namespace，并满足 Landlock、seccomp 能力。


## 从哪个文件开始读

- `package.json`：包入口、运行要求和 Pi 扩展声明。
- `src/index.ts`：注册 Pi 扩展与 `/permission` 命令。
- `src/approve-core/runtime.ts`：运行审批链。
- `src/sandbox/production.ts`：接管工具并绑定受控执行。

## 贡献方式与 License

欢迎一起开发：先提 issue，维护者同意后再提 PR。MIT License 见 [LICENSE](LICENSE)。
