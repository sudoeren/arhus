import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { consoleRule } from '../../src/rules/console';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-console', () => {
  test('flags console.log', () => {
    const ctx = makeContext('console.log("hello");');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('console.log');
  });

  test('flags console.error', () => {
    const ctx = makeContext('console.error("error!");');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags console.warn', () => {
    const ctx = makeContext('console.warn("warning");');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags console.debug', () => {
    const ctx = makeContext('console.debug({ x: 1 });');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags multiple console calls', () => {
    const ctx = makeContext('console.log("a"); console.error("b");');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(2);
  });

  test('does not flag other methods', () => {
    const ctx = makeContext('logger.log("hello"); obj.error("oops");');
    const findings = consoleRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('has Info severity', () => {
    const ctx = makeContext('console.log("test");');
    const findings = consoleRule.check(ctx);
    expect(findings[0]!.severity).toBe('info');
  });
});
