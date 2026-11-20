export type TokenKind =
  | "plain"
  | "keyword"
  | "string"
  | "comment"
  | "type"
  | "fn"
  | "number"
  | "operator"

export interface CodeToken {
  kind: TokenKind
  text: string
}

const TS_KEYWORDS = new Set([
  "import",
  "from",
  "export",
  "const",
  "let",
  "var",
  "await",
  "async",
  "for",
  "of",
  "if",
  "else",
  "throw",
  "new",
  "return",
  "true",
  "false",
  "null",
  "undefined",
  "type"
])

const TS_TYPES = new Set([
  "AeadWasm",
  "ChaCha20Poly1305",
  "XChaCha20Poly1305",
  "ChaCha20",
  "XChaCha20",
  "Poly1305",
  "Uint8Array",
  "Error",
  "console"
])

const TS_PATTERN =
  /(\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b\d+(?:\.\d+)?\b|\b[A-Za-z_]\w*(?=\s*\()|\b[A-Za-z_]\w*\b|[{}()[\].,:;?+-=<>!|&/*]+|\s+)/g

const BASH_PATTERN =
  /(#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:npm|bun|npx|install|run|build|dev)\b|[^\s#"'`]+|\s+)/g

export function tokenizeCode(code: string, lang: string): CodeToken[] {
  const tokens: CodeToken[] = []

  if (lang === "bash" || lang === "sh") {
    let match: RegExpExecArray | null
    BASH_PATTERN.lastIndex = 0
    while ((match = BASH_PATTERN.exec(code)) !== null) {
      const text = match[0]
      let kind: TokenKind = "plain"
      if (text.startsWith("#")) {
        kind = "comment"
      } else if (text.startsWith('"') || text.startsWith("'")) {
        kind = "string"
      } else if (/^(npm|bun|npx)$/.test(text)) {
        kind = "fn"
      } else if (/^(install|run|build|dev)$/.test(text)) {
        kind = "keyword"
      } else if (text === "aead-wasm") {
        kind = "type"
      }
      tokens.push({ kind, text })
    }
    return tokens
  }

  let match: RegExpExecArray | null
  TS_PATTERN.lastIndex = 0
  let lastIndex = 0

  while ((match = TS_PATTERN.exec(code)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ kind: "plain", text: code.slice(lastIndex, match.index) })
    }
    const text = match[0]
    let kind: TokenKind = "plain"

    if (text.startsWith("//")) {
      kind = "comment"
    } else if (text.startsWith('"') || text.startsWith("'") || text.startsWith("`")) {
      kind = "string"
    } else if (/^\d/.test(text)) {
      kind = "number"
    } else if (TS_KEYWORDS.has(text)) {
      kind = "keyword"
    } else if (TS_TYPES.has(text)) {
      kind = "type"
    } else if (/^[A-Za-z_]\w*$/.test(text)) {
      // Lookahead check: if next char in code after match is '(' it was matched as fn or identifier
      const nextChar = code[match.index + text.length]
      if (nextChar === "(") {
        kind = "fn"
      }
    } else if (/^[{}()[\].,:;?+-=<>!|&/*]+$/.test(text)) {
      kind = "operator"
    }

    tokens.push({ kind, text })
    lastIndex = match.index + text.length
  }

  if (lastIndex < code.length) {
    tokens.push({ kind: "plain", text: code.slice(lastIndex) })
  }

  return tokens
}
