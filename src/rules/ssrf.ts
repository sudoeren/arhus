import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const HTTP_CLIENTS = new Set([
  'fetch', 'get', 'request', 'got', 'ky',
  'axios', 'node-fetch', 'cross-fetch',
]);

const URL_BUILDERS = new Set([
  'URL', 'URLSearchParams',
]);

export const ssrfRule: Rule = {
  id: 'no-ssrf',
  name: 'No SSRF',
  description: 'Detects Server-Side Request Forgery where user input is used to build URLs.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function isDynamicArg(node: ts.Node): boolean {
      if (ts.isTemplateExpression(node) && node.templateSpans.length > 0) return true;
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return true;
      if (ts.isIdentifier(node)) return true;
      if (ts.isCallExpression(node)) return true;
      return false;
    }

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        let calleeText = '';

        if (ts.isIdentifier(node.expression)) {
          calleeText = node.expression.text;
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          calleeText = node.expression.name.text;
        }

        if (calleeText && (HTTP_CLIENTS.has(calleeText) || calleeText === 'request')) {
          const firstArg = node.arguments[0];
          if (firstArg && isDynamicArg(firstArg)) {
            const span = ts.isPropertyAccessExpression(node.expression)
              ? node.expression.name.getStart(sourceFile)
              : node.expression.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-ssrf',
              message: `"${calleeText}()" called with dynamic URL, potential SSRF vulnerability`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + calleeText.length,
              suggestion: 'Validate/whitelist the URL scheme, host, and path; block private IP ranges',
            });
          }
        }
      }

      if (ts.isNewExpression(node) && node.arguments && ts.isIdentifier(node.expression) &&
          URL_BUILDERS.has(node.expression.text) && node.arguments.length > 0) {
        const firstArg = node.arguments[0]!;
        if (isDynamicArg(firstArg)) {
          const span = node.expression.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-ssrf',
            message: `"new ${node.expression.text}()" with dynamic input could be used for SSRF`,
            severity: Severity.Medium,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + node.expression.text.length,
            suggestion: 'Validate URL components before constructing',
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
