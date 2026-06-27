import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { unsafeRegexRule } from '../../src/rules/unsafe-regex';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-unsafe-regex', () => {
  test('flags regex literal with nested quantifier (a+)+', () => {
    const ctx = makeContext('const re = /(a+)+/;');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('nested quantifier');
  });

  test('flags regex literal with (.*)* pattern', () => {
    const ctx = makeContext('const re = /([a-z]+)*/i;');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags RegExp() with unsafe pattern string', () => {
    const ctx = makeContext('const re = new RegExp("(\\\\w+)+");');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags overlapping alternation', () => {
    const ctx = makeContext('const re = /a|aa|aaa/;');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('alternation');
  });

  test('does not flag safe regex literal', () => {
    const ctx = makeContext('const re = /^[a-z0-9]+$/;');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag safe RegExp() string', () => {
    const ctx = makeContext('const re = new RegExp("^hello$");');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('flags global RegExp call', () => {
    const ctx = makeContext('const re = RegExp("(\\\\d+)+");');
    const findings = unsafeRegexRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });
});
