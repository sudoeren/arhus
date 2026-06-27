import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ArhusConfig } from './types';

const defaults: ArhusConfig = {
  include: ['**/*.{ts,tsx,js,jsx}'],
  exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**', '**/*.test.*', '**/test/**', 'tests/**'],
  rules: {},
};

export function loadConfig(cwd: string): ArhusConfig {
  const configPath = resolve(cwd, '.arhusrc');

  try {
    const raw = readFileSync(configPath, 'utf-8');
    const user = JSON.parse(raw) as Partial<ArhusConfig>;

    return {
      include: user.include ?? defaults.include,
      exclude: user.exclude ?? defaults.exclude,
      rules: { ...defaults.rules, ...user.rules },
    };
  } catch {
    return defaults;
  }
}
