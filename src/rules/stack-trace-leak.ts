import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const ERROR_PROPERTIES = new Set([
  'stack', 'message', 'name',
]);

const RESPONSE_METHODS = new Set([
  'send', 'json', 'end', 'write',
]);

export const stackTraceLeakRule: Rule = {
  id: 'no-stack-trace-leak',
  name: 'No Stack Trace Leak',
  description: 'Detects error stack traces being sent to clients, which leaks implementation details.',
  severity: Severity.Medium,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text;

        if (RESPONSE_METHODS.has(methodName) && node.arguments.length > 0) {
          const firstArg = node.arguments[0]!;

          if (ts.isPropertyAccessExpression(firstArg) && ERROR_PROPERTIES.has(firstArg.name.text)) {
            const span = firstArg.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-stack-trace-leak',
              message: `Error "${firstArg.name.text}" sent to client in response, leaks internal details`,
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + firstArg.name.text.length,
              suggestion: 'Log the error server-side and send a generic error message to the client',
            });
          }

          if (ts.isIdentifier(firstArg) && (firstArg.text.toLowerCase().includes('error') ||
              firstArg.text.toLowerCase().includes('err'))) {
            const span = firstArg.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-stack-trace-leak',
              message: `Error object "${firstArg.text}" sent to client response, may leak stack traces`,
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + firstArg.text.length,
              suggestion: 'Extract only safe properties or use a generic error message',
            });
          }
        }
      }

      if (ts.isPropertyAccessExpression(node) && node.name.text === 'stack' &&
          ts.isIdentifier(node.expression) && node.expression.text === 'err') {
        ts.forEachChild(node, walk);
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
