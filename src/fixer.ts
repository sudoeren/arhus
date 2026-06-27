import { readFileSync, writeFileSync } from 'node:fs';
import type { Finding } from './types';

export interface FixResult {
  file: string;
  fixed: number;
  skipped: number;
}

export function applyFixes(findings: Finding[], dryRun: boolean): FixResult[] {
  const byFile = new Map<string, Finding[]>();

  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  const results: FixResult[] = [];

  for (const [file, fileFindings] of byFile) {
    let fixed = 0;
    let skipped = 0;

    try {
      let source = readFileSync(file, 'utf-8');

      for (const finding of fileFindings) {
        if (!finding.suggestion) {
          skipped++;
          continue;
        }
        // basic replacement: suggestion is the replacement text
        const lines = source.split('\n');
        const lineIdx = finding.line - 1;
        if (lineIdx < lines.length) {
          const line = lines[lineIdx]!;
          const col = finding.column - 1;
          const endCol = (finding.endColumn ?? col + 1) - 1;
          const before = line.slice(0, col);
          const after = line.slice(endCol);
          lines[lineIdx] = before + finding.suggestion + after;
          fixed++;
        }
      }

      if (!dryRun && fixed > 0) {
        writeFileSync(file, lines.join('\n'), 'utf-8');
      }
    } catch {
      skipped = fileFindings.length;
    }

    results.push({ file, fixed, skipped });
  }

  return results;
}
