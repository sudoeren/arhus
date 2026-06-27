# AGENTS.md

## Project: arhus

scan. fix. repeat. — local-first security analysis with TypeScript AST-based auto-fix.

## Critical Rules

1. **NEVER commit or push without explicit user permission.** Do not run `git commit`, `git push`, or `git add` unless the user explicitly asks.
2. **NEVER create documentation files (*.md) or README files unless the user explicitly asks.**

## Tech Stack

- Runtime: bun (dev), Node.js 20 LTS (target)
- Packages: chalk, commander, fast-glob, typescript, @inquirer/prompts, ora
- Test: bun test
- CI: GitHub Actions

## Commands

| Command | Description |
|---|---|
| `arhus` | Interactive mode |
| `arhus scan <path>` | Security scan |
| `arhus fix <path>` | Auto-fix |
| `arhus init` | Create .arhusrc |
| `bun test` | Run tests |
| `bun run build` | Build for Node.js |
