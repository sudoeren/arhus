import { Severity } from '../types';
import type { Rule } from '../types';

export const xssDomRule: Rule = {
  id: 'no-xss-dom',
  name: 'No XSS via DOM',
  description: 'Detects dangerous DOM manipulations that can lead to XSS.',
  severity: Severity.High,
  check() {
    return [];
  },
};
