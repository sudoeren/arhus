import ts from 'typescript';

export function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function isUserControlledInternal(node: ts.Node): boolean {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return true;
  if (ts.isTemplateExpression(node) && node.templateSpans.length > 0) return true;
  if (ts.isIdentifier(node)) return true;
  if (ts.isPropertyAccessExpression(node)) return true;
  if (ts.isCallExpression(node)) return true;
  return false;
}

export function isDynamic(node: ts.Node): boolean {
  return isUserControlledInternal(node);
}

export function hasUserInput(node: ts.Node): boolean {
  return isUserControlledInternal(node);
}

export function isUserControlled(node: ts.Node): boolean {
  return isUserControlledInternal(node);
}
