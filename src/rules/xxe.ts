import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

export const xxeRule: Rule = {
  id: 'no-xxe',
  name: 'No XXE',
  description: 'Detects XML parsing with external entities enabled that can lead to XXE.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function checkObjectLiteral(obj: ts.ObjectLiteralExpression) {
      for (const prop of obj.properties) {
        if (ts.isPropertyAssignment(prop)) {
          const name = prop.name.getText(sourceFile).replace(/['"]/g, '').toLowerCase();
          const isDangerous =
            (name === 'noent' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) ||
            (name === 'ent' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) ||
            (name === 'dtd' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) ||
            (name === 'loadexternaldtd' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) ||
            (name === 'externalentities' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) ||
            (name === 'noblanks' && prop.initializer.kind === ts.SyntaxKind.FalseKeyword);

          if (isDangerous) {
            const span = prop.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);
            findings.push({
              ruleId: 'no-xxe',
              message: `XML parser with "${name}: ${prop.initializer.getText(sourceFile)}" enables external entities, potential XXE`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + name.length,
              suggestion: 'Set noent:false and disable DTD/external entities',
            });
          }
        }
      }
    }

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        let methodName = '';
        if (ts.isPropertyAccessExpression(callee)) methodName = callee.name.text;
        else if (ts.isIdentifier(callee)) methodName = callee.text;

        if (methodName === 'parseXml' || methodName === 'parseXmlString' || methodName === 'fromXml') {
          const span = ts.isPropertyAccessExpression(callee) ? callee.name.getStart(sourceFile) : callee.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);
          findings.push({
            ruleId: 'no-xxe',
            message: `"${methodName}()" may allow XXE if external entities are not disabled`,
            severity: Severity.High,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + methodName.length,
            suggestion: 'Disable external entities (noent:false, dtd:false) and external DTD loading',
          });
        }

        for (const arg of node.arguments) {
          if (ts.isObjectLiteralExpression(arg)) checkObjectLiteral(arg);
        }
      }

      if (ts.isNewExpression(node) && node.arguments) {
        for (const arg of node.arguments) {
          if (ts.isObjectLiteralExpression(arg)) checkObjectLiteral(arg);
        }
        // Also detect new Parser({noent:true}) via libxml / xmldom
        if (ts.isIdentifier(node.expression)) {
          const name = node.expression.text.toLowerCase();
          if (name.includes('parser') && node.arguments.length > 0) {
            // already checked object literal above
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
