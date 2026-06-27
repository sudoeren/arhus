import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

export const debuggerRule: Rule = {
  id: 'no-debugger',
  name: 'No Debugger',
  description: 'Detects debugger statements that should not be committed.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (node.kind === ts.SyntaxKind.DebuggerStatement) {
        const loc = getLocation(sourceFile, node.getStart(sourceFile));

        findings.push({
          ruleId: 'no-debugger',
          message: 'Debugger statement found, remove before committing',
          severity: Severity.High,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + 8,
        });
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
