import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const SQL_KEYWORDS = /\b(SELECT\s|INSERT\s+INTO\s|UPDATE\s|DELETE\s+FROM\s|DROP\s+TABLE\s|CREATE\s+TABLE\s|ALTER\s+TABLE\s|TRUNCATE\s|GRANT\s|REVOKE\s)/i;

const DB_METHODS = new Set([
  'query', 'execute', 'run', 'exec', 'all', 'get',
  'raw', 'sql',
]);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function isSqlString(text: string): boolean {
  return SQL_KEYWORDS.test(text);
}

function isDbCall(callee: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(callee) && DB_METHODS.has(callee.name.text)) {
    return true;
  }
  return false;
}

export const sqlInjectionRule: Rule = {
  id: 'no-sql-injection',
  name: 'No SQL Injection',
  description: 'Detects SQL queries built via string concatenation with user input.',
  severity: Severity.Critical,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;
    const sourceText = context.sourceText;

    function walk(node: ts.Node) {
      if (ts.isTemplateExpression(node) && node.templateSpans.length > 0) {
        const fullText = sourceText.slice(node.getStart(sourceFile), node.getEnd());
        if (isSqlString(fullText)) {
          const loc = getLocation(sourceFile, node.getStart(sourceFile));

          findings.push({
            ruleId: 'no-sql-injection',
            message: 'SQL query built with template literal interpolation, vulnerable to SQL injection',
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + 30,
            suggestion: 'Use parameterized queries with placeholders (?, $1) and pass values separately',
          });
        }
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        const leftStr = ts.isStringLiteral(node.left) ? node.left.text : '';
        const rightStr = ts.isStringLiteral(node.right) ? node.right.text : '';

        if ((leftStr && isSqlString(leftStr)) || (rightStr && isSqlString(rightStr))) {
          const stringNode = leftStr ? node.left : node.right;
          const loc = getLocation(sourceFile, stringNode.getStart(sourceFile));

          findings.push({
            ruleId: 'no-sql-injection',
            message: 'SQL query built with string concatenation, vulnerable to SQL injection',
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + Math.min(stringNode.getWidth(sourceFile), 40),
            suggestion: 'Use parameterized queries with placeholders (?, $1) and pass values separately',
          });
        }
      }

      if (ts.isCallExpression(node) && isDbCall(node.expression)) {
        for (const arg of node.arguments) {
          if (ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
            const leftStr = ts.isStringLiteral(arg.left) ? arg.left.text : '';
            const rightStr = ts.isStringLiteral(arg.right) ? arg.right.text : '';
            if ((leftStr && isSqlString(leftStr)) || (rightStr && isSqlString(rightStr))) {
              const loc = getLocation(sourceFile, arg.getStart(sourceFile));
              findings.push({
                ruleId: 'no-sql-injection',
                message: 'SQL query passed to database method via string concatenation',
                severity: Severity.Critical,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + Math.min(arg.getWidth(sourceFile), 40),
                suggestion: 'Use parameterized queries with placeholders (?, $1) and pass values separately',
              });
            }
          }

          if (ts.isTemplateExpression(arg) && arg.templateSpans.length > 0) {
            const fullText = sourceText.slice(arg.getStart(sourceFile), arg.getEnd());
            if (isSqlString(fullText)) {
              const loc = getLocation(sourceFile, arg.getStart(sourceFile));
              findings.push({
                ruleId: 'no-sql-injection',
                message: 'SQL query via template literal passed to database method',
                severity: Severity.Critical,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + 30,
                suggestion: 'Use parameterized queries with placeholders (?, $1) and pass values separately',
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
