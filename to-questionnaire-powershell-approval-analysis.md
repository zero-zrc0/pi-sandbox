# PowerShell 审批解析与风险评估方案调研问卷

**Purpose:** 选择适合审批链的 PowerShell 解析和风险评估方案，并形成可实施的节点设计，以减少安全、可判定操作上的人工询问，同时保留对高风险和无法判定输入的审查。

**From:** pi-sandbox 用户，**To:** 独立的工具安全研究 agent（可联网搜索；没有本会话上下文），**How your answers will be used:** 为 pi-sandbox 制定 PowerShell 审批节点的实现计划。

## Context

请检查当前工作区 `E:\AgentCode\pi-extentions\pi-sandbox`。PowerShell 是沙箱注册的内置工具：`src/sandbox/types.ts` 将 `powershell` 列入 `BUILTIN_TOOL_NAMES`，`src/sandbox/pi.ts` 注册其工具定义。审批模块的分类器 `src/approve-core/utils/access-intent/tool-kind.ts` 只将 `bash` 识别为 Bash，其余未知工具名归为 `extension`。结构分析 `src/approve-core/nodes/analysis/index.ts` 只把 `bash` 和 `shell` 交给 Bash 分析器；`powershell` 会成为 whole-call 单元。默认评估器 `src/approve-core/nodes/assessment/index.ts` 对没有已验证文件事实的 extension 不提供专门评估。现有 `src/approve-core/nodes/assessment/shell.ts` 风险规则基于 Bash 命令事实。配置 `shellTools` 可以声明命令参数名用于权限目标提取，但不解析 PowerShell 语法。用户希望补充合适的 PowerShell 审批节点，减少不必要的询问，不要求消除不确定或高风险操作的审查。

当前工作区可能包含未提交修改。请以实际文件为准，不要覆盖、清理或修改工作区；本任务只需要调研结论和设计建议。

## How to answer

没有指定截止时间；建议投入 30–45 分钟。请检查上述源码，并联网查找官方或其他一手资料，优先使用 Microsoft PowerShell 文档、API 文档和 PowerShell 源码。为关键事实提供直接链接；标出推断、版本前提和未能确定之处。可以部分回答；遇到未知项请明确说明。

## Parser strategy

### 哪种解析基础最适合审批时分析 PowerShell 命令？

比较 PowerShell 官方 AST/parser API、自建词法或语法分析、以及复用现有 Bash 分析框架的可行性。说明运行时和跨平台约束，并给出推荐及依据。

>

### 哪些 PowerShell 语法构造需要重点识别为间接或动态执行？

请说明别名、调用运算符、脚本块、动态命令名、变量展开、子进程和命令字符串执行等构造会怎样影响分析完整性，并引用一手资料。

>

## Risk assessment and routing

### 审批分析器应识别哪些副作用类别？

请给出一份适合映射到 allow、review/ask、deny 或 block 的风险分类，并区分可由 AST 静态确定的操作与只能保守估计的操作。

>

### 对动态、混淆或无法完整解析的输入，如何减少询问且保持安全？

请建议明确的路由规则，说明哪些已知安全模式可以自动通过、哪些风险必须升级审查，以及哪些输入必须保留人工询问或阻止。

>

## Approval-chain integration and validation

### 在当前链路中，最小且可维护的 PowerShell 分析接入点是什么？

比较新增 PowerShell 专用节点、在通用 shell 分析节点内加入按语言分派、或其他方案。请说明如何保留工具身份、命令和副作用事实、单元级决策及审计证据，并推荐一种方案。

>

### 哪些验收案例能证明方案减少了不必要询问且没有放过高风险命令？

请列出代表性的 PowerShell 输入、预期风险分类与审批结果，尤其覆盖只读操作、文件/网络/进程副作用、动态执行、解析失败和嵌套 PowerShell 调用。

>

## Anything else?

还有哪些会改变方案选择的重要事实、限制或风险？

>
