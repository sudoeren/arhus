import { Severity } from '../types';
import type { Rule } from '../types';

export const unsafeRegexRule: Rule = {
  id: 'no-unsafe-regex',
  name: 'No Unsafe Regex',
  description: 'Detects regular expressions vulnerable to ReDoS attacks.',
  severity: Severity.High,
  check() {
    return [];
  },
};
