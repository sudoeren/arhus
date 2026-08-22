import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { getLocation, isDynamic, hasUserInput, isUserControlled } from '../src/utils';

function nodeFromCode(code: string): ts.Node {
  const sf = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  let found: ts.Node | null = null;
  function walk(n: ts.Node) {
    if (!found && (ts.isBinaryExpression(n) || ts.isTemplateExpression(n) || ts.isIdentifier(n) || ts.isCallExpression(n) || ts.isPropertyAccessExpression(n))) {
      found = n;
    }
    ts.forEachChild(n, walk);
  }
  // For specific codes, just get first relevant node via helper
  return sf.statements[0]!;
}

describe('utils', () => {
  test('getLocation returns line and column', () => {
    const sf = ts.createSourceFile('test.ts', 'const a = 1;\nconst b = 2;', ts.ScriptTarget.Latest, true);
    const loc = getLocation(sf, 0);
    expect(loc.line).toBe(1);
    expect(loc.column).toBe(1);
    const loc2 = getLocation(sf, 13);
    expect(loc2.line).toBe(2);
  });

  test('isDynamic detects binary plus', () => {
    const sf = ts.createSourceFile('test.ts', 'const x = a + b;', ts.ScriptTarget.Latest, true);
    let found: ts.Node | null = null;
    function walk(n: ts.Node) { if (ts.isBinaryExpression(n) && !found) found = n; ts.forEachChild(n, walk); }
    walk(sf);
    expect(isDynamic(found!)).toBe(true);
  });

  test('isDynamic detects template', () => {
    const sf = ts.createSourceFile('test.ts', 'const x = `hi ${a}`;', ts.ScriptTarget.Latest, true);
    let found: ts.Node | null = null;
    function walk(n: ts.Node) { if (ts.isTemplateExpression(n)) found = n; ts.forEachChild(n, walk); }
    walk(sf);
    expect(isDynamic(found!)).toBe(true);
  });

  test('isDynamic and hasUserInput are aliases of isUserControlled', () => {
    const sf = ts.createSourceFile('test.ts', 'const x = foo();', ts.ScriptTarget.Latest, true);
    let call: ts.Node | null = null;
    function walk(n: ts.Node) { if (ts.isCallExpression(n)) call = n; ts.forEachChild(n, walk); }
    walk(sf);
    expect(isDynamic(call!)).toBe(true);
    expect(hasUserInput(call!)).toBe(true);
    expect(isUserControlled(call!)).toBe(true);
  });

  test('isDynamic returns false for literal', () => {
    const sf = ts.createSourceFile('test.ts', 'const x = 42;', ts.ScriptTarget.Latest, true);
    const decl = (sf.statements[0] as ts.VariableStatement).declarationList.declarations[0]!;
    const init = decl.initializer!;
    expect(isDynamic(init)).toBe(false);
    expect(hasUserInput(init)).toBe(false);
  });
});
