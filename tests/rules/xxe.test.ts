import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { xxeRule } from '../../src/rules/xxe';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-xxe', () => {
  test('flags noent true', () => {
    const ctx = makeContext('new Parser({noent: true});');
    expect(xxeRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags parseXml', () => {
    const ctx = makeContext('parser.parseXml(data);');
    expect(xxeRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags dtd true', () => {
    const ctx = makeContext('xmlParser({dtd: true});');
    expect(xxeRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag noent false', () => {
    const ctx = makeContext('new Parser({noent: false});');
    expect(xxeRule.check(ctx).length).toBe(0);
  });
  test('does not flag safe parsing', () => {
    const ctx = makeContext('parser.parseJson(data);');
    expect(xxeRule.check(ctx).length).toBe(0);
  });
});
