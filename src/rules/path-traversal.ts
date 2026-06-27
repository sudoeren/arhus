import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const FS_OPS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'createReadStream', 'createWriteStream', 'open', 'openSync',
  'readdir', 'readdirSync', 'rmdir', 'rmdirSync',
  'unlink', 'unlinkSync', 'stat', 'statSync',
  'access', 'accessSync', 'exists', 'existsSync',
  'mkdir', 'mkdirSync', 'rm', 'rmSync',
  'rename', 'renameSync', 'copyFile', 'copyFileSync',
  'lstat', 'lstatSync',
]);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function hasUserInput(node: ts.Node): boolean {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return true;
  if (ts.isTemplateExpression(node) && node.templateSpans.length > 0) return true;
  if (ts.isCallExpression(node)) return true;
  return false;
}

export const pathTraversalRule: Rule = {
  id: 'no-path-traversal',
  name: 'No Path Traversal',
  description: 'Detects potential path traversal vulnerabilities in file operations.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        let funcName = '';

        if (ts.isPropertyAccessExpression(node.expression)) {
          funcName = node.expression.name.text;
        } else if (ts.isIdentifier(node.expression)) {
          funcName = node.expression.text;
        }

        if (FS_OPS.has(funcName) && node.arguments.length > 0) {
          const firstArg = node.arguments[0]!;

          if (hasUserInput(firstArg)) {
            const nameSpan = ts.isPropertyAccessExpression(node.expression)
              ? node.expression.name.getStart(sourceFile)
              : node.expression.getStart(sourceFile);
            const loc = getLocation(sourceFile, nameSpan);

            findings.push({
              ruleId: 'no-path-traversal',
              message: `"${funcName}()" called with dynamic file path, potential path traversal`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + funcName.length,
              suggestion: 'Use path.resolve() and path.normalize() to sanitize the path',
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
