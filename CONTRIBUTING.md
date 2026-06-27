# Contributing to arhus

## Setup

```bash
git clone https://github.com/sudoeren/arhus.git
cd arhus
bun install
bun link
```

## Development

```bash
# Interactive mode
arhus

# Scan the project itself
arhus scan .

# Run all tests
bun test

# Run tests in watch mode
bun test --watch

# Build for Node.js
bun run build
```

## Adding a Rule

1. Create a new file in `src/rules/<rule-name>.ts`
2. Implement the `Rule` interface:
   ```ts
   import { Severity } from '../types';
   import type { Rule } from '../types';

   export const myRule: Rule = {
     id: 'my-rule-id',
     name: 'My Rule',
     description: 'What it detects',
     severity: Severity.High,
     check(context) {
       // Walk context.sourceFile AST with visitor pattern
       // Return Finding[] for each match
     },
   };
   ```
3. Register it in `src/rules/index.ts`:
   ```ts
   import { registerRule } from '../rule';
   import { myRule } from './my-rule';

   registerRule(myRule);
   ```
4. Write tests in `tests/rules/my-rule.test.ts`
5. Run `bun test` to verify

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` — new feature
- `fix:` — bug fix
- `chore:` — maintenance
- `docs:` — documentation
- `test:` — tests
- `ci:` — CI/CD changes
