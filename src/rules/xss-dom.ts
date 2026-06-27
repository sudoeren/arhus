import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const DANGEROUS_PROPERTIES = new Set([
  'innerHTML',
  'outerHTML',
]);

const DANGEROUS_METHODS = new Set([
  'write',
  'writeln',
]);

const DANGEROUS_GLOBALS = new Set([
  'eval',
]);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function isDocumentAccess(expr: ts.Expression): boolean {
  if (ts.isIdentifier(expr) && expr.text === 'document') return true;
  if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'document') return true;
  return false;
}

export const xssDomRule: Rule = {
  id: 'no-xss-dom',
  name: 'No XSS via DOM',
  description: 'Detects dangerous DOM manipulations that can lead to XSS.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isPropertyAccessExpression(node) && DANGEROUS_PROPERTIES.has(node.name.text)) {
        const span = node.name.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);
        const isWrite = ts.isBinaryExpression(node.parent) &&
          node.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          node.parent.left === node;

        const severity = isWrite ? Severity.Critical : Severity.High;
        const action = isWrite ? 'assigned' : 'accessed';

        findings.push({
          ruleId: 'no-xss-dom',
          message: `Dangerous "${node.name.text}" property ${action}, may lead to XSS`,
          severity,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + node.name.text.length,
          suggestion: isWrite ? 'textContent' : undefined,
        });
      }

      if (ts.isCallExpression(node)) {
        const callee = node.expression;

        if (ts.isPropertyAccessExpression(callee) && isDocumentAccess(callee.expression)) {
          if (DANGEROUS_METHODS.has(callee.name.text)) {
            const span = callee.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-xss-dom',
              message: `Dangerous "document.${callee.name.text}()" can inject HTML, leading to XSS`,
              severity: Severity.Critical,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + callee.name.text.length,
              suggestion: 'Use safe DOM APIs (createElement, appendChild, textContent)',
            });
          }
        }

        if (ts.isIdentifier(callee) && DANGEROUS_GLOBALS.has(callee.text)) {
          const span = callee.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-xss-dom',
            message: `"${callee.text}()" executes arbitrary code, potential XSS/RCE vector`,
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + callee.text.length,
          });
        }

        const globalName = ts.isIdentifier(callee) ? callee.text : '';
        const methodName = ts.isPropertyAccessExpression(callee) ? callee.name.text : '';

        if ((globalName === 'setTimeout' || globalName === 'setInterval' || methodName === 'setTimeout' || methodName === 'setInterval')) {
          if (node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
            const name = globalName || methodName;
            const span = ts.isPropertyAccessExpression(callee) ? callee.name.getStart(sourceFile) : callee.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-xss-dom',
              message: `"${name}()" with string argument acts like eval(), potential XSS`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + name.length,
              suggestion: `Use ${name}(() => { ... }, delay) with a function instead of a string`,
            });
          }
        }

        if (methodName === 'insertAdjacentHTML') {
          const span = callee.name.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-xss-dom',
            message: '"insertAdjacentHTML()" parses and injects HTML, potential XSS',
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + methodName.length,
          });
        }

      }

      if (ts.isJsxAttribute(node) && node.name.getText(sourceFile) === 'dangerouslySetInnerHTML') {
        const span = node.name.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);

        findings.push({
          ruleId: 'no-xss-dom',
          message: '"dangerouslySetInnerHTML" bypasses React XSS protections',
          severity: Severity.Critical,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + 'dangerouslySetInnerHTML'.length,
          suggestion: 'Use React children or a sanitization library (DOMPurify)',
        });
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
