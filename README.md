# argus-cli

> DevSecOps security scanner — 100% local code analysis with TypeScript AST-based auto-fix.

## Install

```bash
bun install
```

## Usage

```bash
# Scan a directory
bun run bin/argus.ts scan ./src

# Auto-fix issues (dry run)
bun run bin/argus.ts fix ./src --dry-run

# Apply fixes
bun run bin/argus.ts fix ./src

# JSON / SARIF output
bun run bin/argus.ts scan ./src --format json
bun run bin/argus.ts scan ./src --format sarif

# Create config file
bun run bin/argus.ts init
```

## Rules

| Rule | Severity |
|---|---|
| `no-hardcoded-secrets` | Critical |
| `no-unsafe-regex` | High |
| `no-xss-dom` | High |
| `no-path-traversal` | High |
| `no-sql-injection` | Critical |
| `no-command-injection` | Critical |
