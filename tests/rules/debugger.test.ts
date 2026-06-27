import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { debuggerRule } from '../../src/rules/debugger';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-debugger', () => {
  test('flags debugger statement', () => {
    const ctx = makeContext('function foo() { debugger; }');
    const findings = debuggerRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe('no-debugger');
    expect(findings[0]!.message).toContain('Debugger');
  });

  test('flags multiple debugger statements', () => {
    const ctx = makeContext('function a() { debugger; } function b() { debugger; }');
    const findings = debuggerRule.check(ctx);
    expect(findings.length).toBe(2);
  });

  test('does not flag code without debugger', () => {
    const ctx = makeContext('console.log("hello"); const x = 1;');
    const findings = debuggerRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('flags debugger in conditional', () => {
    const ctx = makeContext('if (x === null) { debugger; }');
    const findings = debuggerRule.check(ctx);
    expect(findings.length).toBe(1);
  });
});
