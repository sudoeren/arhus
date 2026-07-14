import ts from 'typescript';
import fg from 'fast-glob';
import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { getActiveRules } from './rule';
import type { Finding, Rule, ScanResult, RuleContext, ArhusConfig } from './types';

export interface ProgressCallback {
  onFileScanned(file: string, index: number, total: number): void;
}

const IGNORE_RE = /\/\/\s*arhus-ignore-line(?::\s*(\S+))?/;

function isIgnored(sourceText: string, finding: Finding): boolean {
  const lines = sourceText.split('\n');
  const lineIdx = finding.line - 1;
  if (lineIdx < 0 || lineIdx >= lines.length) return false;
  const match = lines[lineIdx]!.match(IGNORE_RE);
  if (!match) return false;
  const ruleFilter = match[1];
  if (!ruleFilter) return true;
  return ruleFilter === finding.ruleId;
}

export async function scanFiles(targetPath: string, config: ArhusConfig, onProgress?: ProgressCallback): Promise<ScanResult[]> {
  const cwd = resolve(targetPath);

  const files = await fg(config.include, {
    cwd,
    ignore: config.exclude,
    absolute: true,
    onlyFiles: true,
  });

  const rules = getActiveRules(config);
  const results: ScanResult[] = [];
  const total = files.length;

  for (let i = 0; i < total; i++) {
    const file = files[i]!;
    onProgress?.onFileScanned(file, i + 1, total);
    const findings = scanFile(file, rules);
    if (findings.length > 0) {
      results.push({ file: relative(cwd, file), findings });
    }
  }

  return results;
}

export function scanFile(filePath: string, rules: Rule[]): Finding[] {
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
      const ruleFindings = rule.check(context);
      for (const finding of ruleFindings) {
        if (!isIgnored(sourceText, finding)) {
          findings.push(finding);
        }
      }
    } catch {
      // skip rule on error, continue with others
    }
  }

  return findings;
}
