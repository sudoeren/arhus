import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { insecureDeserializationRule } from '../../src/rules/insecure-deserialization';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-insecure-deserialization', () => {
  test('flags JSON.parse with identifier', () => {
    const ctx = makeContext('JSON.parse(userInput);');
    expect(insecureDeserializationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags eval with identifier', () => {
    const ctx = makeContext('eval(userCode);');
    expect(insecureDeserializationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags Function with identifier', () => {
    const ctx = makeContext('Function(userInput)();');
    expect(insecureDeserializationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag JSON.parse with literal', () => {
    const ctx = makeContext('JSON.parse(\'{"a":1}\');');
    expect(insecureDeserializationRule.check(ctx).length).toBe(0);
  });
  test('does not flag JSON.parse with no args', () => {
    const ctx = makeContext('JSON.parse();');
    expect(insecureDeserializationRule.check(ctx).length).toBe(0);
  });
});
