import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { ssrfRule } from '../../src/rules/ssrf';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-ssrf', () => {
  test('flags fetch with dynamic url', () => {
    const ctx = makeContext('fetch(userUrl);');
    expect(ssrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags fetch with template literal', () => {
    const ctx = makeContext('fetch(`https://api.com/${userInput}`);');
    expect(ssrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags axios.get with identifier', () => {
    const ctx = makeContext('axios.get(req.query.url);');
    expect(ssrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags new URL with dynamic input', () => {
    const ctx = makeContext('new URL(userInput);');
    expect(ssrfRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag fetch with literal', () => {
    const ctx = makeContext('fetch("https://example.com/api");');
    expect(ssrfRule.check(ctx).length).toBe(0);
  });
  test('does not flag new URL with literal', () => {
    const ctx = makeContext('new URL("https://example.com");');
    expect(ssrfRule.check(ctx).length).toBe(0);
  });
});
