---
name: arhus
description: Use arhus CLI to scan codebases for security vulnerabilities. Use when the user asks to run a security scan, find security issues, fix vulnerabilities, lint for security, detect hardcoded secrets, XSS, SQL injection, NoSQL injection, command injection, SSRF, path traversal, unsafe regex, weak crypto, prototype pollution, insecure deserialization, CORS misconfiguration, certificate validation bypass, stack trace leak, insecure randomness, insecure HTTP, or when the agent should validate code before committing or deploying. Triggers include "scan for vulnerabilities", "security scan", "check security", "arhus", "run arhus", "find security issues", "security audit", "check my code", "prototype pollution", "nosql injection", "ssrf".
---

# arhus

arhus is a local-first security scanner for TypeScript and JavaScript. It uses AST analysis to detect 20 types of security vulnerabilities with zero telemetry.

## Preconditions

- arhus is installed globally via `npm i -g arhus-cli`.
- Run it from any directory with `arhus scan <path>`.
- The default config (`.arhusrc`) excludes `node_modules/`, `dist/`, `.git/`, `coverage/`, and test files.
- Never modify `.arhusrc` unless the user asks.

## Usage

### Scan

```bash
# Scan current directory
arhus scan .

# Scan specific path
arhus scan ./src

# JSON output
arhus scan . --format json

# SARIF output
arhus scan . --format sarif

# Interactive mode (menu-driven)
arhus
```

### Auto-fix

```bash
# Preview fixes
arhus fix . --dry-run

# Apply fixes
arhus fix .
```

### Create config

```bash
arhus init
```

## Rules (20 rules)

| Rule ID | Severity | Description |
|---|---|---|
| `no-hardcoded-secrets` | Critical | API keys, tokens, passwords in source |
| `no-sql-injection` | Critical | SQL queries built via string concatenation |
| `no-nosql-injection` | Critical/High | NoSQL injection in MongoDB query operators |
| `no-command-injection` | Critical/High | exec/spawn with dynamic input |
| `no-weak-cert-validation` | Critical | Disabled TLS/SSL certificate validation |
| `no-xss-dom` | Critical/High | innerHTML, document.write, eval |
| `no-insecure-deserialization` | High/Critical | JSON.parse/eval on untrusted input |
| `no-prototype-pollution` | High/Critical | Unsafe merge/assign leading to prototype pollution |
| `no-insecure-randomness` | High/Critical | Math.random() in security-sensitive contexts |
| `no-ssrf` | High/Medium | Server-Side Request Forgery via user-controlled URLs |
| `no-unsafe-regex` | High | ReDoS patterns, nested quantifiers |
| `no-path-traversal` | High | File ops with user-controlled paths |
| `no-weak-crypto` | High | MD5, SHA1, DES, RC4 |
| `no-unvalidated-redirect` | High | Open redirect via dynamic URLs |
| `no-unrestricted-file-upload` | High | File upload without extension validation |
| `no-cors-misconfiguration` | High | Overly permissive CORS configurations |
| `no-debugger` | Medium/High | debugger statements in code |
| `no-stack-trace-leak` | Medium | Error stack traces sent to clients |
| `no-insecure-http` | Medium/Low | Plain HTTP instead of HTTPS |
| `no-console` | Info | console.log in production code |

## Rule Configuration

In `.arhusrc`:

```json
{
  "rules": {
    "no-console": false,
    "no-debugger": "critical"
  }
}
```

- `false` - disable the rule
- `"critical"`, `"high"`, etc. - override severity
- `{ "severity": "high" }` - object form

## Interpreting Findings

A finding shows:
```
file.ts:15:10: CRITICAL: String matches known secret prefix "sk-" [no-hardcoded-secrets]
```

- The `file:line:column` is clickable in VS Code terminal.
- All findings cause a non-zero exit code (CI fails).
- Run `arhus fix . --dry-run` to see auto-fix suggestions.

## When to Use

- After writing or modifying code, run a scan to catch security issues early.
- Before a commit or PR, validate the codebase.
- When the user mentions "security", "vulnerability", "scan", or "audit".
- When implementing auto-fix for detected issues.

## Configuration File

arhus loads `.arhusrc` by searching upward from the target directory. If not found, defaults are used:

```json
{
  "include": ["**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules/**", "dist/**", ".git/**", "coverage/**", "**/*.test.*", "**/test/**", "tests/**"],
  "rules": {}
}
```
