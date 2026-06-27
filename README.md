# arhus

> scan. fix. repeat. — local-first security analysis with TypeScript AST-based auto-fix.

## Install

```bash
git clone https://github.com/sudoeren/arhus.git
cd arhus
bun install
bun link
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

## Configuration

```bash
arhus init   # creates .arhusrc
```

```json
{
  "include": ["**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules/**", "dist/**", ".git/**", "coverage/**", "**/*.test.*", "tests/**"],
  "rules": {}
}
```
