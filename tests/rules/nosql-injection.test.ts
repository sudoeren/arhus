import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { nosqlInjectionRule } from '../../src/rules/nosql-injection';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-nosql-injection', () => {
  test('flags $where operator', () => {
    const ctx = makeContext('db.collection.find({"$where": userInput});');
    expect(nosqlInjectionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags $regex operator', () => {
    const ctx = makeContext('users.findOne({"$regex": req.query.input});');
    expect(nosqlInjectionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags db.eval', () => {
    const ctx = makeContext('db.eval("return 1")');
    expect(nosqlInjectionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag safe query without $', () => {
    const ctx = makeContext('users.find({name: "john"});');
    expect(nosqlInjectionRule.check(ctx).length).toBe(0);
  });
  test('does not flag non-mongo method', () => {
    const ctx = makeContext('myFunc({"$where": "x"});');
    expect(nosqlInjectionRule.check(ctx).length).toBe(0);
  });
});
