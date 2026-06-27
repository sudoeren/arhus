import ts from 'typescript';
import fg from 'fast-glob';
import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { getRules } from './rule';
import type { Finding, Rule, ScanResult, RuleContext } from './types';

export async function scanFiles(targetPath: string, include: string[], exclude: string[]): Promise<ScanResult[]> {
  const cwd = resolve(targetPath);

  const files = await fg(include, {
    cwd,
    ignore: exclude,
    absolute: true,
    onlyFiles: true,
  });

  const rules = getRules();
  const results: ScanResult[] = [];

  for (const file of files) {
    const findings = scanFile(file, rules);
    if (findings.length > 0) {
      results.push({ file: relative(cwd, file), findings });
    }
  }

  return results;
}

function scanFile(filePath: string, rules: Rule[]): Finding[] {
  let sourceText: string;
  try {
    sourceText = readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const context: RuleContext = { fileName: filePath, sourceText, sourceFile };
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      findings.push(...rule.check(context));
    } catch {
      // skip rule on error, continue with others
    }
  }

  return findings;
}
