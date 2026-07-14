import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation, isDynamic } from '../utils';

const WRITE_METHODS = new Set(['writeFile', 'writeFileSync', 'createWriteStream', 'copyFile', 'copyFileSync', 'rename', 'renameSync']);

export const unrestrictedFileUploadRule: Rule = {
  id: 'no-unrestricted-file-upload',
  name: 'No Unrestricted File Upload',
  description: 'Detects file upload handling without extension validation.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const callee = node.expression;
        const methodName = callee.name.text;

        if (methodName === 'mv' && node.arguments.length > 0) {
          const dest = node.arguments[0]!;

          if (isDynamic(dest)) {
            const span = callee.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-unrestricted-file-upload',
              message: 'File upload via mv() with dynamic path, extension not validated',
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 2,
              suggestion: 'Validate file extension against a whitelist before saving',
            });
          }
        }

        if (WRITE_METHODS.has(methodName) && node.arguments.length > 0) {
          const pathArg = node.arguments[0]!;
          if (isDynamic(pathArg)) {
            const span = callee.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-unrestricted-file-upload',
              message: `File written via ${methodName}() with dynamic path, potential unrestricted upload`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + methodName.length,
              suggestion: 'Validate file extension and sanitize the filename',
            });
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
