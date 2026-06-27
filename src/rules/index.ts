import { registerRule } from '../rule';

import { hardcodedSecretsRule } from './hardcoded-secrets';
import { unsafeRegexRule } from './unsafe-regex';
import { xssDomRule } from './xss-dom';
import { pathTraversalRule } from './path-traversal';
import { sqlInjectionRule } from './sql-injection';
import { commandInjectionRule } from './command-injection';
import { debuggerRule } from './debugger';
import { weakCryptoRule } from './weak-crypto';
import { unvalidatedRedirectRule } from './unvalidated-redirect';
import { consoleRule } from './console';

export function registerAllRules(): void {
  registerRule(hardcodedSecretsRule);
  registerRule(unsafeRegexRule);
  registerRule(xssDomRule);
  registerRule(pathTraversalRule);
  registerRule(sqlInjectionRule);
  registerRule(commandInjectionRule);
  registerRule(debuggerRule);
  registerRule(weakCryptoRule);
  registerRule(unvalidatedRedirectRule);
  registerRule(consoleRule);
}
