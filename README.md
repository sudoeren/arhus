<p align="center">
  <img src="https://raw.githubusercontent.com/sudoeren/arhus/main/assets/logo.png" alt="arhus logo" width="160">
</p>

# arhus

> scan. fix. repeat. local-first security analysis for TypeScript & JavaScript.

<p align="center">
  <a href="https://www.npmjs.com/package/arhus-cli"><img src="https://img.shields.io/npm/dt/arhus-cli?label=total%20downloads" alt="npm total downloads"></a>
  <a href="https://www.npmjs.com/package/arhus-cli"><img src="https://img.shields.io/npm/v/arhus-cli" alt="npm version"></a>

</p>

## Install

```bash
npm i -g arhus-cli
```



### AI Agent Skill

```bash
npx skills add sudoeren/arhus
```

## Usage

```bash
# Interactive mode (menu-driven)
arhus

# Scan a directory
arhus scan ./src

# Auto-fix (dry run — preview only)
arhus fix ./src --dry-run

# Apply fixes
arhus fix ./src

# JSON output
arhus scan ./src --format json

# SARIF output (GitHub Code Scanning)
arhus scan ./src --format sarif

# Create config file
arhus init
```

## Rules

| Rule | Severity | Description |
|---|---|---|
| `no-hardcoded-secrets` | Critical | API keys, tokens, passwords in source |
| `no-sql-injection` | Critical | SQL queries via string concatenation |
| `no-command-injection` | Critical | exec/spawn with dynamic input |
| `no-xss-dom` | Critical/High | innerHTML, document.write, eval |
| `no-unsafe-regex` | High | ReDoS patterns, nested quantifiers |
| `no-path-traversal` | High | File ops with user-controlled paths |

## Why arhus

arhus runs **entirely offline**. No telemetry, no cloud, no API calls. Your source code never leaves your machine. Unlike ESLint plugins that focus on style and surface-level patterns, arhus performs AST-aware semantic checks — tracing taint from user input through function calls — without the overhead of a full SAST platform.

## Configuration

```bash
arhus init   # creates .arhusrc
```

```json
{
  "include": ["**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules/**", "dist/**", ".git/**", "coverage/**", "**/*.test.*", "tests/**"],
  "rules": {
    "no-console": false,
    "no-debugger": "critical"
  }
}
```

### Rule Configuration

| Value | Effect |
|---|---|
| `true` or omitted | Rule runs with default severity |
| `false` | Rule is disabled |
| `"low"`, `"medium"`, `"high"`, `"critical"` | Override severity |
| `{ "severity": "high" }` | Object form with severity override + future options |

## License

MIT — see [LICENSE](LICENSE) for details.
