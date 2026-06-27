import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import type { ArhusConfig } from './types';

const defaults: ArhusConfig = {
  include: ['**/*.{ts,tsx,js,jsx}'],
  exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**', '**/*.test.*', '**/test/**', 'tests/**'],
  rules: {},
};

function findConfigUp(from: string): string | null {
  let dir = resolve(from);
  const root = dirname(dir);

  while (true) {
    const p = resolve(dir, '.arhusrc');
    if (existsSync(p)) return p;
    if (dir === root) break;
    dir = dirname(dir);
  }

  const rootConfig = resolve(root, '.arhusrc');
  if (existsSync(rootConfig)) return rootConfig;

  return null;
}

export function loadConfig(cwd: string): ArhusConfig {
  const configPath = findConfigUp(cwd);

  if (configPath) {
    try {
      const raw = readFileSync(configPath, 'utf-8');
      const user = JSON.parse(raw) as Partial<ArhusConfig>;

      return {
        include: user.include ?? defaults.include,
        exclude: user.exclude ?? defaults.exclude,
        rules: { ...defaults.rules, ...user.rules },
      };
    } catch {
      // fall through to defaults
    }
  }

  return defaults;
}
