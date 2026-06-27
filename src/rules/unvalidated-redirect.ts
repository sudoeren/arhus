import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const REDIRECT_METHODS = new Set(['redirect', 'replace', 'assign']);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function isDynamic(node: ts.Node): boolean {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return true;
  if (ts.isTemplateExpression(node) && node.templateSpans.length > 0) return true;
  if (ts.isCallExpression(node)) return true;
  if (ts.isIdentifier(node)) return true;
  return false;
}

export const unvalidatedRedirectRule: Rule = {
  id: 'no-unvalidated-redirect',
  name: 'No Unvalidated Redirect',
  description: 'Detects redirects with user-controlled input (open redirect vulnerability).',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        let methodName = '';

        if (ts.isPropertyAccessExpression(node.expression)) {
          methodName = node.expression.name.text;

          if (REDIRECT_METHODS.has(methodName) && node.arguments.length > 0) {
            const firstArg = node.arguments[0]!;

            if (isDynamic(firstArg)) {
              const span = node.expression.name.getStart(sourceFile);
              const loc = getLocation(sourceFile, span);

              findings.push({
                ruleId: 'no-unvalidated-redirect',
                message: `"${methodName}()" called with dynamic URL, open redirect vulnerability`,
                severity: Severity.High,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + methodName.length,
                suggestion: 'Validate/whitelist redirect URLs or use a safe redirect mapping',
              });
            }
          }
        }
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        if (ts.isPropertyAccessExpression(node.left)) {
          const prop = node.left;
          const targetName = prop.name.text;

          if ((targetName === 'location' && ts.isIdentifier(prop.expression) && prop.expression.text === 'window') ||
              targetName === 'href' || targetName === 'location') {

            if (isDynamic(node.right)) {
              const span = prop.name.getStart(sourceFile);
              const loc = getLocation(sourceFile, span);

              findings.push({
                ruleId: 'no-unvalidated-redirect',
                message: `"${targetName}" assigned with dynamic URL, open redirect vulnerability`,
                severity: Severity.High,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + targetName.length,
                suggestion: 'Validate/whitelist redirect URLs before assignment',
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
