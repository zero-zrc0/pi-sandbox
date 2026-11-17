# AGENTS.md

## 项目介绍

`pi-sandbox` 是 Pi coding agent 扩展，为工具调用提供策略审批，并将批准范围绑定到受控执行。它支持 Linux 和 Windows 上的受控工具执行；MCP 工具由宿主 transport 执行。

## 使用

- 运行要求：Node.js `>=22.19.0`，并使用满足 `package.json` 中 peer dependency 要求的 Pi 宿主。
- 在 Pi 中安装：`pi install npm:@sirzero/pi-sandbox`；输入 `/permission` 查看和管理当前会话的审批模式。
- 本地开发：运行 `npm ci` 安装依赖；用 `npm run check` 检查类型、`npm test` 运行测试、`npm run build` 构建。
- 阅读入口：`src/index.ts` 注册扩展命令；`src/approve-core/runtime.ts` 运行审批链；`src/sandbox/production.ts` 接管工具并绑定受控执行。

## Git 分支命名

新建分支使用格式：`<前缀>/<修改内容>-<YYYYMMDD>`。

- 前缀表示工作类型，例如 `feat`、`fix`、`debug`、`refactor`、`docs`、`test`、`chore`。
- 修改内容简洁描述本分支的工作；日期使用分支创建日，格式为四位年、两位月、两位日。
- 示例：`feat/runtime-catalog-20261117`、`debug/windows-launch-20261117`、`docs/git-branch-rules-20261117`。
