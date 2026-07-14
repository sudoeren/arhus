import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const HTTP_MODULES = new Set([
  'http', 'http2',
]);

export const insecureHttpRule: Rule = {
  id: 'no-insecure-http',
  name: 'No Insecure HTTP',
  description: 'Detects usage of plain HTTP instead of HTTPS for network communication.',
  severity: Severity.Medium,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        const calleeText = node.expression.text;

        if (calleeText === 'createServer' || calleeText === 'request') {
          const span = node.expression.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-insecure-http',
            message: `"${calleeText}()" on http module transmits data in plain text`,
            severity: Severity.Medium,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + calleeText.length,
            suggestion: 'Use the "https" module instead',
          });
        }
      }

      if (ts.isStringLiteral(node)) {
        const text = node.text.toLowerCase();
        if (text.startsWith('http://')) {
          const span = node.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-insecure-http',
            message: 'Hardcoded "http://" URL detected, use "https://" instead',
            severity: Severity.Low,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + node.text.length + 2,
            suggestion: 'Use "https://" instead',
          });
        }
      }

      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) &&
          node.expression.text === 'require' && node.arguments.length > 0 &&
          ts.isStringLiteral(node.arguments[0]!) && HTTP_MODULES.has(node.arguments[0]!.text)) {
        const arg = node.arguments[0]!;
        const span = arg.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);

        findings.push({
          ruleId: 'no-insecure-http',
          message: `Importing plain "${arg.text}" module, consider "https" for secure communication`,
          severity: Severity.Info,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + arg.text.length + 2,
          suggestion: 'Use the "https" module: require("https")',
        });
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
