import { describe, test, expect } from 'bun:test';
import { terminalReport, jsonReport, sarifReport } from '../src/reporter';
import { Severity } from '../src/types';
import type { ScanResult } from '../src/types';

const emptyResults: ScanResult[] = [];

const sampleResults: ScanResult[] = [
  {
    file: 'src/test.ts',
    findings: [
      {
        ruleId: 'no-console',
        message: 'console.log() found',
        severity: Severity.Info,
        file: 'src/test.ts',
        line: 5,
        column: 3,
        endColumn: 7,
      },
      {
        ruleId: 'no-hardcoded-secrets',
        message: 'Hardcoded password found',
        severity: Severity.Critical,
        file: 'src/test.ts',
        line: 10,
        column: 1,
        endColumn: 20,
      },
    ],
  },
  {
    file: 'src/app.ts',
    findings: [
      {
        ruleId: 'no-debugger',
        message: 'Debugger statement found',
        severity: Severity.Medium,
        file: 'src/app.ts',
        line: 3,
        column: 1,
        endColumn: 9,
      },
    ],
  },
];

describe('terminalReport', () => {
  test('returns green message for empty results', () => {
    const report = terminalReport(emptyResults);
    expect(report).toContain('No security issues found');
  });

  test('includes finding details in output', () => {
    const report = terminalReport(sampleResults);
    expect(report).toContain('src/test.ts');
    expect(report).toContain('src/app.ts');
    expect(report).toContain('console.log() found');
    expect(report).toContain('Hardcoded password found');
    expect(report).toContain('Debugger statement found');
    expect(report).toContain('3 findings');
  });

  test('includes severity badges', () => {
    const report = terminalReport(sampleResults);
    expect(report).toContain('CRITICAL');
    expect(report).toContain('MEDIUM');
    expect(report).toContain('INFO');
  });
});

describe('jsonReport', () => {
  test('returns valid JSON for empty results', () => {
    const report = jsonReport(emptyResults);
    expect(JSON.parse(report)).toEqual([]);
  });

  test('returns valid JSON with all findings', () => {
    const report = jsonReport(sampleResults);
    const parsed = JSON.parse(report);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]!.findings).toHaveLength(2);
    expect(parsed[1]!.findings).toHaveLength(1);
  });
});

describe('sarifReport', () => {
  test('returns valid SARIF 2.1.0 JSON', () => {
    const report = sarifReport(sampleResults);
    const parsed = JSON.parse(report);
    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
  });

  test('includes rules in SARIF output', () => {
    const report = sarifReport(sampleResults);
    const parsed = JSON.parse(report);
    const rules = parsed.runs[0]!.tool.driver.rules;
    expect(rules).toHaveLength(3);
  });

  test('includes results with locations', () => {
    const report = sarifReport(sampleResults);
    const parsed = JSON.parse(report);
    const results = parsed.runs[0]!.results;
    expect(results).toHaveLength(3);
    expect(results[0]!.locations[0]!.physicalLocation.region.startLine).toBe(5);
  });
});
