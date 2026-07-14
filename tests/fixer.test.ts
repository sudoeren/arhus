import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { applyFixes } from '../src/fixer';
import type { Finding } from '../src/types';
import { Severity } from '../src/types';

let testDir: string;
let testFile: string;

beforeAll(() => {
  testDir = mkdtempSync(join(tmpdir(), 'arhus-fixer-'));
});

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: 'test-rule',
    message: 'test',
    severity: Severity.Low,
    file: testFile,
    line: 1,
    column: 1,
    endColumn: 2,
    suggestion: 'replacement',
    ...overrides,
  };
}

describe('applyFixes', () => {
  test('replaces text on single line', () => {
    testFile = join(testDir, 'single-line.ts');
    writeFileSync(testFile, 'const x = "old";\n', 'utf-8');
    const findings = [makeFinding({ line: 1, column: 11, endColumn: 16, suggestion: '"new"' })];
    applyFixes(findings, false);
    const content = readFileSync(testFile, 'utf-8');
    expect(content).toBe('const x = "new";\n');
  });

  test('dry run does not modify file', () => {
    testFile = join(testDir, 'dry-run.ts');
    writeFileSync(testFile, 'const x = "old";\n', 'utf-8');
    const findings = [makeFinding({ line: 1, column: 11, endColumn: 16, suggestion: '"new"' })];
    applyFixes(findings, true);
    const content = readFileSync(testFile, 'utf-8');
    expect(content).toBe('const x = "old";\n');
  });

  test('skips findings without suggestion', () => {
    testFile = join(testDir, 'no-suggestion.ts');
    writeFileSync(testFile, 'const x = "old";\n', 'utf-8');
    const findings = [makeFinding({ suggestion: undefined })];
    const results = applyFixes(findings, false);
    expect(results[0]!.fixed).toBe(0);
    expect(results[0]!.skipped).toBe(1);
  });

  test('handles multiple findings on same line', () => {
    testFile = join(testDir, 'multi-same-line.ts');
    writeFileSync(testFile, 'const a = x, b = y;\n', 'utf-8');
    const findings = [
      makeFinding({ line: 1, column: 11, endColumn: 12, suggestion: '"newA"' }),
      makeFinding({ line: 1, column: 18, endColumn: 19, suggestion: '"newB"' }),
    ];
    applyFixes(findings, false);
    const content = readFileSync(testFile, 'utf-8');
    expect(content).toBe('const a = "newA", b = "newB";\n');
  });

  test('handles multi-line findings', () => {
    testFile = join(testDir, 'multi-line.ts');
    writeFileSync(testFile, 'const x = fn(\n  arg1,\n  arg2\n);\n', 'utf-8');
    const findings = [makeFinding({
      line: 1,
      column: 11,
      endLine: 3,
      endColumn: 7,
      suggestion: '"simple"',
    })];
    applyFixes(findings, false);
    const content = readFileSync(testFile, 'utf-8');
    expect(content).toBe('const x = "simple"\n);\n');
  });

  test('returns fix results grouped by file', () => {
    testFile = join(testDir, 'result-test.ts');
    writeFileSync(testFile, 'const x = "old";\n', 'utf-8');
    const findings = [makeFinding({ line: 1, column: 11, endColumn: 16, suggestion: '"new"' })];
    const results = applyFixes(findings, false);
    expect(results).toHaveLength(1);
    expect(results[0]!.file).toBe(testFile);
    expect(results[0]!.fixed).toBe(1);
    expect(results[0]!.skipped).toBe(0);
  });

  test('handles non-existent file gracefully', () => {
    const findings = [makeFinding({ file: '/nonexistent/file.ts' })];
    const results = applyFixes(findings, false);
    expect(results[0]!.fixed).toBe(0);
    expect(results[0]!.skipped).toBe(1);
  });
});
