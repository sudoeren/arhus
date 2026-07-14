import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation, hasUserInput } from '../utils';

const EXEC_FUNCTIONS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync']);

export const commandInjectionRule: Rule = {
  id: 'no-command-injection',
  name: 'No Command Injection',
  description: 'Detects unsafe command execution with unsanitized user input.',
  severity: Severity.Critical,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        let funcName = '';

        if (ts.isIdentifier(node.expression)) {
          funcName = node.expression.text;
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          funcName = node.expression.name.text;
        }

        if (EXEC_FUNCTIONS.has(funcName)) {
          const firstArg = node.arguments[0];
          if (firstArg && hasUserInput(firstArg)) {
            const nameSpan = ts.isPropertyAccessExpression(node.expression)
              ? node.expression.name.getStart(sourceFile)
              : node.expression.getStart(sourceFile);
            const loc = getLocation(sourceFile, nameSpan);

            findings.push({
              ruleId: 'no-command-injection',
              message: `"${funcName}()" called with dynamically built command string, potential command injection`,
              severity: Severity.Critical,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + funcName.length,
              suggestion: 'Use spawn() with separate argument array, or shell-escape/validators on input',
            });
          }

          if (funcName === 'spawn' || funcName === 'spawnSync') {
            for (const arg of node.arguments) {
              if (ts.isObjectLiteralExpression(arg)) {
                for (const prop of arg.properties) {
                  if (ts.isPropertyAssignment(prop) && prop.name.getText(sourceFile) === 'shell') {
                    if (prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
                      const loc = getLocation(sourceFile, prop.name.getStart(sourceFile));
                      findings.push({
                        ruleId: 'no-command-injection',
                        message: 'spawn() with shell:true enables command injection via shell interpretation',
                        severity: Severity.High,
                        file: context.fileName,
                        line: loc.line,
                        column: loc.column,
                        endLine: loc.line,
                        endColumn: loc.column + 5,
                        suggestion: 'Remove shell:true or use array-form arguments with escaping',
                      });
                    }
                  }
                }
              }
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
