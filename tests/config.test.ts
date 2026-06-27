import { describe, test, expect } from 'bun:test';
import { loadConfig } from '../src/config';

describe('config', () => {
  test('loads defaults when no .argusrc exists', () => {
    const config = loadConfig('/tmp/nonexistent');
    expect(config.include).toEqual(['**/*.{ts,tsx,js,jsx}']);
    expect(config.exclude).toContain('node_modules/**');
    expect(config.rules).toEqual({});
  });
});
