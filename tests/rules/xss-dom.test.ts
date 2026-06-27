import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { xssDomRule } from '../../src/rules/xss-dom';
import type { RuleContext, Severity } from '../../src/types';

function makeContext(code: string, fileName = 'test.tsx'): RuleContext {
  const sourceFile = ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true, fileName.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  return {
    fileName,
    sourceText: code,
    sourceFile,
  };
}

function hasMessage(findings: { message: string }[], substr: string): boolean {
  return findings.some(f => f.message.includes(substr));
}

describe('no-xss-dom', () => {
  test('flags innerHTML assignment as Critical', () => {
    const ctx = makeContext('document.getElementById("app").innerHTML = userInput;');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    const f = findings.find(f => f.message.includes('innerHTML') && f.message.includes('assigned'));
    expect(f).toBeDefined();
    expect(f!.severity).toBe('critical');
  });

  test('flags innerHTML read as High', () => {
    const ctx = makeContext('const html = element.innerHTML;');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'innerHTML')).toBe(true);
    expect(hasMessage(findings, 'accessed')).toBe(true);
  });

  test('flags outerHTML assignment', () => {
    const ctx = makeContext('element.outerHTML = "<div>" + input + "</div>";');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'outerHTML')).toBe(true);
  });

  test('flags document.write()', () => {
    const ctx = makeContext('document.write(userInput);');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'document.write')).toBe(true);
  });

  test('flags document.writeln()', () => {
    const ctx = makeContext('document.writeln("<p>" + name + "</p>");');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'document.writeln')).toBe(true);
  });

  test('flags eval()', () => {
    const ctx = makeContext('eval("alert(" + xss + ")");');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'eval')).toBe(true);
  });

  test('flags insertAdjacentHTML()', () => {
    const ctx = makeContext('element.insertAdjacentHTML("beforeend", userInput);');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'insertAdjacentHTML')).toBe(true);
  });

  test('flags dangerouslySetInnerHTML in JSX', () => {
    const ctx = makeContext('<div dangerouslySetInnerHTML={{ __html: userInput }} />');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'dangerouslySetInnerHTML')).toBe(true);
  });

  test('flags setTimeout with string argument', () => {
    const ctx = makeContext('setTimeout("alert(1)", 1000);');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'setTimeout')).toBe(true);
  });

  test('flags setInterval with string argument', () => {
    const ctx = makeContext('setInterval("fetchData()", 5000);');
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(hasMessage(findings, 'setInterval')).toBe(true);
  });

  test('does not flag textContent assignment', () => {
    const ctx = makeContext('element.textContent = userInput;');
    const findings = xssDomRule.check(ctx);
    const hasInnerHtml = findings.some(f => f.message.includes('innerHTML'));
    expect(hasInnerHtml).toBe(false);
  });

  test('does not flag setTimeout with function argument', () => {
    const ctx = makeContext('setTimeout(() => { console.log("hi"); }, 1000);');
    const findings = xssDomRule.check(ctx);
    const hasSetTimeout = findings.some(f => f.message.includes('setTimeout'));
    expect(hasSetTimeout).toBe(false);
  });

  test('does not flag safe DOM methods', () => {
    const ctx = makeContext(`
      document.querySelector("#app");
      document.createElement("div");
      element.appendChild(child);
      element.classList.add("active");
    `);
    const findings = xssDomRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('innerHTML assignment gets textContent suggestion', () => {
    const ctx = makeContext('div.innerHTML = value;');
    const findings = xssDomRule.check(ctx);
    const f = findings.find(f => f.message.includes('innerHTML'));
    expect(f).toBeDefined();
    expect(f!.suggestion).toBe('textContent');
  });
});
