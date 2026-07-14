import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const MONGO_METHODS = new Set([
  'find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete',
  'updateOne', 'updateMany', 'deleteOne', 'deleteMany',
  'aggregate', 'count', 'countDocuments', 'distinct',
]);

export const nosqlInjectionRule: Rule = {
  id: 'no-nosql-injection',
  name: 'No NoSQL Injection',
  description: 'Detects potential NoSQL injection vulnerabilities in MongoDB operations.',
  severity: Severity.Critical,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;
    const sourceText = context.sourceText;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text;

        if (MONGO_METHODS.has(methodName) && node.arguments.length > 0) {
          const firstArg = node.arguments[0]!;

          if (ts.isObjectLiteralExpression(firstArg)) {
            for (const prop of firstArg.properties) {
              if (ts.isPropertyAssignment(prop) && ts.isStringLiteral(prop.name)) {
                const key = prop.name.text;
                if (key.startsWith('$')) {
                  const span = prop.name.getStart(sourceFile);
                  const loc = getLocation(sourceFile, span);

                  findings.push({
                    ruleId: 'no-nosql-injection',
                    message: `Unsanitized operator "${key}" passed to ${methodName}(), potential NoSQL injection`,
                    severity: Severity.Critical,
                    file: context.fileName,
                    line: loc.line,
                    column: loc.column,
                    endLine: loc.line,
                    endColumn: loc.column + key.length,
                    suggestion: 'Validate and sanitize user input before using query operators',
                  });
                }
              }
            }
          }

          if (ts.isIdentifier(firstArg) || ts.isCallExpression(firstArg) || ts.isTemplateExpression(firstArg)) {
            if (ts.isTemplateExpression(firstArg) && firstArg.templateSpans.length > 0) {
              const fullText = sourceText.slice(firstArg.getStart(sourceFile), firstArg.getEnd());
              if (fullText.includes('$where') || fullText.includes('$regex')) {
                const span = node.expression.name.getStart(sourceFile);
                const loc = getLocation(sourceFile, span);

                findings.push({
                  ruleId: 'no-nosql-injection',
                  message: `Template literal passed to ${methodName}() may contain injection operators`,
                  severity: Severity.High,
                  file: context.fileName,
                  line: loc.line,
                  column: loc.column,
                  endLine: loc.line,
                  endColumn: loc.column + methodName.length,
                  suggestion: 'Use a validator like mongo-sanitize to strip $ operators',
                });
              }
            }
          }
        }
      }

      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text;
        if (methodName === 'eval' && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'db') {
          const span = node.expression.name.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);

          findings.push({
            ruleId: 'no-nosql-injection',
            message: 'db.eval() executes arbitrary JavaScript on MongoDB, severe injection risk',
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + 4,
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
