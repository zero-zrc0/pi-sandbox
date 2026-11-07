const FRONTMATTER_FENCE = "---";
const COMMENT_MARKER = "#";

interface IndentFrame {
  readonly container: Record<string, unknown>;
  readonly indent: number;
}

export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n");
}

export function extractFrontmatter(document: string): string {
  const lines = normalizeLineEndings(document).split("\n");
  const [opening] = lines;
  if (!opening.startsWith(FRONTMATTER_FENCE)) {
    return "";
  }
  for (let index = 1; index < lines.length; index += 1) {
    // Compatibility boundary: the closing fence only needs the prefix, so
    // "---x" and "----" terminate a block as well.
    if (lines[index].startsWith(FRONTMATTER_FENCE)) {
      return lines.slice(1, index).join("\n");
    }
  }
  return "";
}

export function parseSimpleFrontmatterMap(frontmatter: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const stack: IndentFrame[] = [];
  for (const line of normalizeLineEndings(frontmatter).split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith(COMMENT_MARKER)) {
      continue;
    }
    const colonIndex = line.indexOf(":");
    if (colonIndex < 0) {
      continue;
    }
    const key = stripMatchingQuotes(line.slice(0, colonIndex).trim());
    if (key.length === 0) {
      continue;
    }
    const indent = line.length - line.trimStart().length;
    while (stack.length > 0 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    let container = root;
    if (stack.length > 0) {
      container = stack[stack.length - 1].container;
    }
    const rawValue = line.slice(colonIndex + 1).trim();
    if (rawValue.length === 0) {
      const child: Record<string, unknown> = {};
      container[key] = child;
      stack.push({ container: child, indent });
    } else {
      container[key] = stripMatchingQuotes(rawValue);
    }
  }
  return root;
}

export function readFrontmatterMap(document: string): Record<string, unknown> {
  return parseSimpleFrontmatterMap(extractFrontmatter(document));
}

function stripMatchingQuotes(value: string): string {
  if (value.length < 2) {
    return value;
  }
  const first = value[0];
  const last = value[value.length - 1];
  if ((first === "'" || first === '"') && first === last) {
    return value.slice(1, -1);
  }
  return value;
}
