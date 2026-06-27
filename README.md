# argus-cli

> scan. fix. repeat. — local-first security analysis with TypeScript AST-based auto-fix.

## Install

```bash
git clone https://github.com/sudoeren/argus-cli.git
cd argus-cli
bun install
bun link
```

## Usage

```bash
# Interactive mode (menu-driven)
argus-cli

# Scan a directory
argus-cli scan ./src

# Auto-fix (dry run — preview only)
argus-cli fix ./src --dry-run

# Apply fixes
argus-cli fix ./src

# JSON output
argus-cli scan ./src --format json

# SARIF output (GitHub Code Scanning)
argus-cli scan ./src --format sarif

# Create config file
argus-cli init
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

## Configuration

```bash
argus-cli init   # creates .argusrc.json
```

```json
{
  "include": ["**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules/**", "dist/**", ".git/**", "coverage/**"],
  "rules": {}
}
```
