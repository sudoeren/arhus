import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { stackTraceLeakRule } from '../../src/rules/stack-trace-leak';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-stack-trace-leak', () => {
  test('flags res.send with err.stack', () => {
    const ctx = makeContext('res.send(err.stack);');
    expect(stackTraceLeakRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags res.json with err.message', () => {
    const ctx = makeContext('res.json(err.message);');
    expect(stackTraceLeakRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags res.send with error identifier', () => {
    const ctx = makeContext('res.send(error);');
    expect(stackTraceLeakRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag res.send with literal', () => {
    const ctx = makeContext('res.send("ok");');
    expect(stackTraceLeakRule.check(ctx).length).toBe(0);
  });
  test('does not flag res.send with safe data', () => {
    const ctx = makeContext('res.send({status: "ok"});');
    expect(stackTraceLeakRule.check(ctx).length).toBe(0);
  });
});
