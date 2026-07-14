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

      const withSuggestions = fileFindings.filter(f => f.suggestion);
      skipped += fileFindings.length - withSuggestions.length;

      const sorted = withSuggestions.sort((a, b) => (b.line - a.line) || (b.column - a.column));

      for (const finding of sorted) {
        const lines = source.split('\n');
        const startLineIdx = finding.line - 1;
        const endLineIdx = (finding.endLine ?? finding.line) - 1;

        if (startLineIdx < 0 || endLineIdx >= lines.length) {
          skipped++;
          continue;
        }

        const startCol = finding.column - 1;
        const endCol = (finding.endColumn ?? startCol + 1) - 1;

        const beforeText = lines[startLineIdx]!.slice(0, startCol);
        const afterText = lines[endLineIdx]!.slice(endCol);

        lines.splice(startLineIdx, endLineIdx - startLineIdx + 1, beforeText + finding.suggestion! + afterText);

        source = lines.join('\n');
        fixed++;
      }

      if (!dryRun && fixed > 0) {
        writeFileSync(file, source, 'utf-8');
      }
    } catch {
      skipped = fileFindings.length;
    }

    results.push({ file, fixed, skipped });
  }

  return results;
}
