/**
 * output-redactor.ts — Post-execution output sanitization.
 *
 * Scans command stdout/stderr for sensitive data patterns and replaces
 * them with [REDACTED] before returning results to the LLM.
 *
 * SECURITY: Over-redacting is preferred to under-redacting.
 *
 * @module output-redactor
 */

const REDACTION_PATTERNS: ReadonlyArray<{
  pattern: RegExp;
  replacement: string;
  label: string;
}> = [
  // Private key blocks (PEM format)
  {
    pattern:
      /-----BEGIN\s[\w\s]*PRIVATE KEY-----[\s\S]*?-----END\s[\w\s]*PRIVATE KEY-----/g,
    replacement: "[REDACTED: private key block]",
    label: "private-key",
  },

  // AWS access key IDs (AKIA...)
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED: AWS access key]",
    label: "aws-key",
  },

  // AWS secret access key after known labels
  {
    pattern:
      /(?:aws_secret_access_key|secret[_-]?access[_-]?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}/gi,
    replacement: "[REDACTED: AWS secret key]",
    label: "aws-secret",
  },

  // Generic password patterns
  {
    pattern: /(?:password|passwd|pass|pwd)\s*[=:]\s*\S+/gi,
    replacement: "[REDACTED: password]",
    label: "password",
  },

  // Authorization / Bearer / Basic auth headers
  {
    pattern: /(?:Authorization|Bearer|Basic)\s*[:=]\s*\S+/gi,
    replacement: "[REDACTED: auth token]",
    label: "auth-header",
  },

  // API keys and tokens
  {
    pattern:
      /(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[=:]\s*\S+/gi,
    replacement: "[REDACTED: api key/token]",
    label: "api-key",
  },

  // Connection strings with embedded credentials
  {
    pattern:
      /(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:]+:[^@]+@/gi,
    replacement: "[REDACTED: connection string]://",
    label: "connection-string",
  },

  // /etc/shadow password hashes (user:$hash:...)
  {
    pattern: /^([^:]+):\$[0-9a-z]+\$[^:]+:/gm,
    replacement: "$1:[REDACTED: password hash]:",
    label: "shadow-hash",
  },

  // GitHub / GitLab personal access tokens
  {
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|glpat)-[A-Za-z0-9_]{20,}\b/g,
    replacement: "[REDACTED: git token]",
    label: "git-token",
  },

  // Generic hex tokens (32+ chars after token/secret/key labels)
  {
    pattern:
      /(?:token|secret|key)\s*[=:]\s*[0-9a-f]{32,}/gi,
    replacement: "[REDACTED: hex token]",
    label: "hex-token",
  },
];

export interface RedactionResult {
  /** The sanitized text */
  text: string;
  /** Number of redactions applied */
  redactionCount: number;
  /** Labels of patterns that matched */
  matchedPatterns: string[];
}

/**
 * Redact sensitive data from command output.
 *
 * @param text - Raw stdout or stderr text
 * @returns Sanitized text with redaction metadata
 */
export function redactOutput(text: string): RedactionResult {
  if (!text) return { text, redactionCount: 0, matchedPatterns: [] };

  let result = text;
  let redactionCount = 0;
  const matchedPatterns: string[] = [];

  for (const { pattern, replacement, label } of REDACTION_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    const matches = result.match(pattern);
    if (matches && matches.length > 0) {
      redactionCount += matches.length;
      matchedPatterns.push(label);
      result = result.replace(pattern, replacement);
    }
  }

  return { text: result, redactionCount, matchedPatterns };
}
