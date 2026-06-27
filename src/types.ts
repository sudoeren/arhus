export enum Severity {
  Critical = 'critical',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Info = 'info',
}

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  suggestion?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  check(context: RuleContext): Finding[];
  fix?(finding: Finding): string;
}

export interface RuleContext {
  fileName: string;
  sourceText: string;
  sourceFile: import('typescript').SourceFile;
}

export interface ScanResult {
  file: string;
  findings: Finding[];
}

export interface RuleOptions {
  severity?: Severity;
  [key: string]: unknown;
}

export interface ArhusConfig {
  include: string[];
  exclude: string[];
  rules: Record<string, boolean | Severity | RuleOptions>;
}
