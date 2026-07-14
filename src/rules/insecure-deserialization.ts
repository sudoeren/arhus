import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

export const insecureDeserializationRule: Rule = {
  id: 'no-insecure-deserialization',
  name: 'No Insecure Deserialization',
  description: 'Detects unsafe deserialization patterns that could lead to RCE or prototype pollution.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        let calleeText = '';
        if (ts.isIdentifier(node.expression)) {
          calleeText = node.expression.text;
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          calleeText = node.expression.name.text;
        }

        if ((calleeText === 'parse' && ts.isPropertyAccessExpression(node.expression) &&
             ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'JSON') ||
            calleeText === 'eval' || calleeText === 'Function') {

          if (node.arguments.length > 0) {
            const firstArg = node.arguments[0]!;
            if (ts.isIdentifier(firstArg) || ts.isCallExpression(firstArg) || ts.isBinaryExpression(firstArg)) {
              const msg = calleeText === 'eval' || calleeText === 'Function'
                ? `"${calleeText}()" deserializes and executes arbitrary code`
                : `JSON.parse() on potentially user-controlled input can lead to prototype pollution`;

              const severity = (calleeText === 'eval' || calleeText === 'Function')
                ? Severity.Critical : Severity.High;

              const span = ts.isPropertyAccessExpression(node.expression)
                ? node.expression.name.getStart(sourceFile)
                : node.expression.getStart(sourceFile);
              const loc = getLocation(sourceFile, span);

              findings.push({
                ruleId: 'no-insecure-deserialization',
                message: msg,
                severity,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + (ts.isPropertyAccessExpression(node.expression)
                  ? node.expression.name.text.length : calleeText.length),
                suggestion: calleeText === 'parse'
                  ? 'Wrap in try-catch and use a reviver function to filter __proto__'
                  : 'Avoid eval/Function with dynamic input',
              });
            }
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
