export function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  expect(parts.length).toBe(3);
  const payloadJson = Buffer.from(parts[1], "base64url").toString("utf-8");
  return JSON.parse(payloadJson) as Record<string, unknown>;
}
