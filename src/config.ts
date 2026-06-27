import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ArgusConfig } from './types';

const defaults: ArgusConfig = {
  include: ['**/*.{ts,tsx,js,jsx}'],
  exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**'],
  rules: {},
};

export function loadConfig(cwd: string): ArgusConfig {
  const configPath = resolve(cwd, '.argusrc.json');

  try {
    const raw = readFileSync(configPath, 'utf-8');
    const user = JSON.parse(raw) as Partial<ArgusConfig>;

    return {
      include: user.include ?? defaults.include,
      exclude: user.exclude ?? defaults.exclude,
      rules: { ...defaults.rules, ...user.rules },
    };
  } catch {
    return defaults;
  }
}
