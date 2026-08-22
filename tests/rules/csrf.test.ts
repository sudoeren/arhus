import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { csrfRule } from '../../src/rules/csrf';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-csrf', () => {
  test('flags post without csrf', () => {
    const ctx = makeContext('app.post("/transfer", (req,res)=>res.send("ok"));');
    expect(csrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags delete without csrf', () => {
    const ctx = makeContext('router.delete("/user", handler);');
    expect(csrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag with csrfProtection arg', () => {
    const ctx = makeContext('app.post("/transfer", csrfProtection, handler);');
    expect(csrfRule.check(ctx).length).toBe(0);
  });
  test('does not flag get method', () => {
    const ctx = makeContext('app.get("/users", handler);');
    expect(csrfRule.check(ctx).length).toBe(0);
  });
});
