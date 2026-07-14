import { describe, test, expect, beforeAll } from 'bun:test';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanFiles, scanFile } from '../src/scanner';
import { registerRule, clearRules } from '../src/rule';
import { Severity } from '../src/types';
import type { Rule, ArhusConfig } from '../src/types';

const dummyRule: Rule = {
  id: 'test-rule',
  name: 'Test Rule',
  description: 'A test rule',
  severity: Severity.Low,
  check: () => [{ ruleId: 'test-rule', message: 'test', severity: Severity.Low, file: 'test.ts', line: 1, column: 1, endColumn: 2 }],
};

function makeRule(findings: { line: number; column: number; endColumn?: number; message?: string }[]): Rule {
  return {
    id: 'test-rule',
    name: 'Test Rule',
    description: 'A test rule',
    severity: Severity.Low,
    check: () => findings.map(f => ({
      ruleId: 'test-rule',
      message: f.message ?? 'test',
      severity: Severity.Low,
      file: 'test.ts',
      line: f.line,
      column: f.column,
      endColumn: f.endColumn ?? f.column + 1,
    })),
  };
}

const config: ArhusConfig = {
  include: ['**/*.{ts,tsx,js,jsx}'],
  exclude: ['node_modules/**'],
  rules: {},
};

describe('scanFile', () => {
  test('returns empty for unreadable files', () => {
    const findings = scanFile('/nonexistent/no-such-file.ts', [dummyRule]);
    expect(findings).toHaveLength(0);
  });

  test('ignores lines with // arhus-ignore-line', () => {
    const code = 'const x = 1; // arhus-ignore-line\nconst y = 2;';
    const rule = makeRule([
      { line: 1, column: 1, endColumn: 2 },
      { line: 2, column: 1, endColumn: 2 },
    ]);

    const dir = mkdtempSync(join(tmpdir(), 'arhus-test-'));
    const filePath = join(dir, 'test.ts');
    writeFileSync(filePath, code, 'utf-8');
    const findings = scanFile(filePath, [rule]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(2);
  });

  test('ignores specific rule with // arhus-ignore-line: rule-id', () => {
    const code = 'const x = 1; // arhus-ignore-line: other-rule\nconst y = 2;\nconst z = 3; // arhus-ignore-line: test-rule';
    const rule = makeRule([
      { line: 1, column: 1 },
      { line: 2, column: 1 },
      { line: 3, column: 1 },
    ]);

    const dir = mkdtempSync(join(tmpdir(), 'arhus-test-'));
    const filePath = join(dir, 'test.ts');
    writeFileSync(filePath, code, 'utf-8');
    const findings = scanFile(filePath, [rule]);
    expect(findings).toHaveLength(2);
    expect(findings[0]!.line).toBe(1);
    expect(findings[1]!.line).toBe(2);
  });

  test('reads real files and returns findings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'arhus-test-'));
    const filePath = join(dir, 'test.ts');
    writeFileSync(filePath, 'const x = 1;\n', 'utf-8');
    const findings = scanFile(filePath, [dummyRule]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('test-rule');
  });
});

describe('scanFiles', () => {
  let testDir: string;

  beforeAll(() => {
    testDir = mkdtempSync(join(tmpdir(), 'arhus-scan-'));
    writeFileSync(join(testDir, 'safe.ts'), 'const x = 1;\nconst y = 2;\n', 'utf-8');
    writeFileSync(join(testDir, 'unsafe.ts'), 'const password = "admin123";\n', 'utf-8');
    mkdirSync(join(testDir, 'nested'));
    writeFileSync(join(testDir, 'nested', 'deep.ts'), 'const x = 1;\n', 'utf-8');
  });

  test('scans files and returns results', async () => {
    clearRules();
    registerRule(dummyRule);
    const results = await scanFiles(testDir, config);
    expect(results.length).toBeGreaterThan(0);
  });

  test('calls progress callback', async () => {
    clearRules();
    registerRule(dummyRule);
    let calls = 0;
    const results = await scanFiles(testDir, config, {
      onFileScanned() { calls++; },
    });
    expect(calls).toBeGreaterThan(0);
  });
});
