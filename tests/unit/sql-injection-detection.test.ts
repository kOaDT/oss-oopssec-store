import { isSQLInjectionAttempt } from "../../lib/sql-injection-detection";

describe("isSQLInjectionAttempt (SQL injection heuristic)", () => {
  it("matches the canonical walkthrough payloads", () => {
    // sql-injection (orders search)
    expect(
      isSQLInjectionAttempt(
        "DELIVERED' UNION SELECT id, email, password, role, addressId FROM users--"
      )
    ).toBe(true);
    // product-search-sql-injection
    expect(isSQLInjectionAttempt("' UNION SELECT 1,2,3,4,5--")).toBe(true);
    // second-order-sql-injection
    expect(isSQLInjectionAttempt("PENDING' OR '1'='1")).toBe(true);
    // x-forwarded-for-sql-injection
    expect(
      isSQLInjectionAttempt(
        "'||(SELECT 'Privacy matters. Dont track your users')||'"
      )
    ).toBe(true);
  });

  it("is case insensitive", () => {
    expect(isSQLInjectionAttempt("union select")).toBe(true);
    expect(isSQLInjectionAttempt("UnIoN sElEcT")).toBe(true);
    expect(isSQLInjectionAttempt("' or 1=1--")).toBe(true);
  });

  it("matches comment and terminator sequences on their own", () => {
    expect(isSQLInjectionAttempt("--")).toBe(true);
    expect(isSQLInjectionAttempt("/*")).toBe(true);
    expect(isSQLInjectionAttempt("*/")).toBe(true);
    expect(isSQLInjectionAttempt("';")).toBe(true);
  });

  it("matches the SQLite concatenation operator on every route", () => {
    // "||" used to live only in the tracking route's copy of this list; the
    // shared helper applies it everywhere. See issue #269.
    expect(isSQLInjectionAttempt("||")).toBe(true);
  });

  it("does not match benign inputs", () => {
    expect(isSQLInjectionAttempt("")).toBe(false);
    expect(isSQLInjectionAttempt("bread")).toBe(false);
    expect(isSQLInjectionAttempt("Olive oil")).toBe(false);
    expect(isSQLInjectionAttempt("PENDING")).toBe(false);
    expect(isSQLInjectionAttempt("alice@example.com")).toBe(false);
    expect(isSQLInjectionAttempt("192.168.1.10")).toBe(false);
  });

  it("does not match stored procedure prefixes (known dead keyword)", () => {
    // "sp_" is compared against an upper-cased input, so it can never match.
    // Locked here so that fixing it is a deliberate change, not a surprise.
    expect(isSQLInjectionAttempt("sp_help")).toBe(false);
    expect(isSQLInjectionAttempt("SP_HELP")).toBe(false);
    // "XP_" is upper case in the list, so it does match.
    expect(isSQLInjectionAttempt("xp_cmdshell")).toBe(true);
  });
});
