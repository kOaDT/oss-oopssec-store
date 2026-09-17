import {
  CANARY_SLUGS,
  generateCanaryToken,
  hasExfiltratedCanary,
} from "../../lib/sql-injection-canary";

describe("generateCanaryToken", () => {
  it("names the challenge it belongs to and stays unguessable", () => {
    const token = generateCanaryToken("x-forwarded-for-sql-injection");

    expect(token).toMatch(
      /^CANARY-X-FORWARDED-FOR-SQL-INJECTION-[0-9a-f]{12}$/
    );
    expect(token).not.toBe(
      generateCanaryToken("x-forwarded-for-sql-injection")
    );
  });

  it("never produces a token the response sanitizer would strip", () => {
    for (const slug of CANARY_SLUGS) {
      expect(generateCanaryToken(slug).toLowerCase()).not.toContain("oss{");
    }
  });
});

describe("hasExfiltratedCanary", () => {
  const canary = { token: "CANARY-SQL-INJECTION-0123456789ab" };

  it("matches a token nested anywhere in the returned rows", () => {
    expect(
      hasExfiltratedCanary([{ id: 1 }, { userAgent: canary.token }], canary, [
        "zzz' UNION SELECT 1, token, 'x', 1, 'y' FROM internal_secrets --",
      ])
    ).toBe(true);
  });

  it("refuses a token the query pasted in as a literal", () => {
    const query = `zzz' UNION SELECT 1, '${canary.token}', 'x', 1, 'y' --`;

    expect(
      hasExfiltratedCanary([{ name: canary.token }], canary, [query])
    ).toBe(false);
  });

  it("refuses a token a stored request field echoed back", () => {
    expect(
      hasExfiltratedCanary([{ ip: canary.token }], canary, [
        canary.token,
        "Mozilla/5.0",
        "/",
        "",
      ])
    ).toBe(false);
  });

  it("rejects a payload that only carries the predictable prefix", () => {
    expect(
      hasExfiltratedCanary([{ ip: "CANARY-SQL-INJECTION-" }], canary, [])
    ).toBe(false);
  });

  it("rejects everything when the canary row is missing", () => {
    expect(hasExfiltratedCanary([{ ip: canary.token }], null, [])).toBe(false);
  });
});
