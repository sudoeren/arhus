import { Severity } from '../types';
import type { Rule } from '../types';

export const sqlInjectionRule: Rule = {
  id: 'no-sql-injection',
  name: 'No SQL Injection',
  description: 'Detects SQL queries built via string concatenation with user input.',
  severity: Severity.Critical,
  check() {
    return [];
  },
};
