import type { Rule } from './types';

const registry = new Map<string, Rule>();

export function registerRule(rule: Rule): void {
  if (registry.has(rule.id)) {
    throw new Error(`Rule "${rule.id}" is already registered`);
  }
  registry.set(rule.id, rule);
}

export function getRule(id: string): Rule | undefined {
  return registry.get(id);
}

export function getRules(): Rule[] {
  return Array.from(registry.values());
}

export function clearRules(): void {
  registry.clear();
}
