const BLOCKED_PATTERNS = [
  /ignore.*previous.*instructions/i,
  /disregard.*instruction/i,
  /reveal.*system.*prompt/i,
  /print.*system.*prompt/i,
];

export function containsBlockedPattern(message: string): boolean {
  return BLOCKED_PATTERNS.some((pattern) => pattern.test(message));
}
