import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { insecureHttpRule } from '../../src/rules/insecure-http';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-insecure-http', () => {
  test('flags http:// url', () => {
    const ctx = makeContext('const url = "http://example.com";');
    expect(insecureHttpRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags require http', () => {
    const ctx = makeContext('const http = require("http");');
    const f = insecureHttpRule.check(ctx);
    expect(f.length).toBeGreaterThan(0);
  });
  test('does not flag https:// url', () => {
    const ctx = makeContext('const url = "https://example.com";');
    expect(insecureHttpRule.check(ctx).length).toBe(0);
  });
  test('does not flag require https', () => {
    const ctx = makeContext('const https = require("https");');
    expect(insecureHttpRule.check(ctx).length).toBe(0);
  });
});
