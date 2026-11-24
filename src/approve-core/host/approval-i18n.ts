export type ApprovalLanguage = "zh" | "en";

export function resolveApprovalLanguage(locale?: string): ApprovalLanguage {
  const selected = locale ?? [process.env.LC_ALL, process.env.LC_MESSAGES,
    process.env.LANGUAGE?.split(":")[0], process.env.LANG].find(value => value?.trim()) ??
    Intl.DateTimeFormat().resolvedOptions().locale;
  return /^zh(?:[-_.@]|$)/i.test(selected.trim()) ? "zh" : "en";
}

const en = {
  request: (tool: string, elevation?: string) => `${tool} requests ${elevation ? `${elevation} execution` : "execution"}`,
  elevation: (tier: string) => `elevation ${tier}`,
  hostBoundary: "Runs once with host permissions, outside the OS sandbox.",
  ordinaryHostUnavailable: "An ordinary approval cannot run this call with Host permissions. Use request_tool_elevation for a supported tool.",
  operation: "Action", scope: "Scope", path: "Path", requestedPath: "Requested path", resolvedPath: "Resolved path", reason: "Reason",
  createFile: "Create file", overwriteFile: "Overwrite file", editFile: "Edit file",
  edits: "Text changes", fileContent: "File content",
  arguments: "Call Arguments", emptyFile: "(empty file)",
  approveOnce: "Approve once", deny: "Deny", allowSession: "Allow for this session", denySession: "Deny for this session",
  help: "↑↓ Select  ·  Enter Confirm  ·  Esc Cancel",
};

const zh: typeof en = {
  request: (tool, elevation) => `工具 ${tool} 请求${elevation ? `${elevation} 执行` : "执行"}`,
  elevation: tier => `提权 ${tier}`,
  hostBoundary: "本次将使用宿主权限执行一次，并脱离操作系统沙箱。",
  ordinaryHostUnavailable: "普通审批不能授予宿主权限。支持的内置工具请使用 request_tool_elevation。",
  operation: "操作", scope: "范围", path: "路径", requestedPath: "请求路径", resolvedPath: "解析路径", reason: "原因",
  createFile: "新建文件", overwriteFile: "覆盖文件", editFile: "编辑文件",
  edits: "文本差异", fileContent: "文件内容",
  arguments: "调用参数", emptyFile: "（空文件）",
  approveOnce: "仅允许本次", deny: "拒绝", allowSession: "本会话允许", denySession: "本会话拒绝",
  help: "↑↓ 选择  ·  Enter 确认  ·  Esc 取消",
};

export const approvalText = { zh, en };
export type ApprovalText = typeof en;
