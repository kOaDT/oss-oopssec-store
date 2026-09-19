import {
  isAccessingProtectedTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "../../lib/sql-injection-detection";

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

describe("isAccessingProtectedTable (flags and hints guard)", () => {
  it("blocks the flags table whatever the quoting or spacing", () => {
    expect(isAccessingProtectedTable("' UNION SELECT flag FROM flags --")).toBe(
      true
    );
    expect(
      isAccessingProtectedTable("' UNION SELECT flag FROM`flags` --")
    ).toBe(true);
    expect(
      isAccessingProtectedTable("' UNION SELECT flag FROM flags WHERE 1=1")
    ).toBe(true);
    expect(
      isAccessingProtectedTable("' UNION SELECT f.flag FROM main.flags f")
    ).toBe(true);
    expect(isAccessingProtectedTable("' JOIN flags ON 1=1 --")).toBe(true);
  });

  it("blocks dropping the table, whatever follows the name", () => {
    expect(isAccessingProtectedTable("x'; DROP TABLE flags; --")).toBe(true);
    expect(isAccessingProtectedTable("x'; DROP TABLE flags;--")).toBe(true);
    expect(isAccessingProtectedTable("x'; DROP TABLE `flags`; --")).toBe(true);
  });

  it("blocks the hints table, which holds the level 3 solutions", () => {
    expect(
      isAccessingProtectedTable("' UNION SELECT content FROM hints --")
    ).toBe(true);
    expect(
      isAccessingProtectedTable(
        "' UNION SELECT group_concat(content) FROM hints--"
      )
    ).toBe(true);
    expect(isAccessingProtectedTable("x'; DROP TABLE `hints`; --")).toBe(true);
  });

  it("leaves the canary table and ordinary input alone", () => {
    expect(
      isAccessingProtectedTable("' UNION SELECT token FROM internal_secrets --")
    ).toBe(false);
    expect(isAccessingProtectedTable("192.168.1.10")).toBe(false);
    expect(
      isAccessingProtectedTable("' UNION SELECT flagId FROM found_flags --")
    ).toBe(false);
    expect(
      isAccessingProtectedTable("' UNION SELECT hintId FROM revealed_hints --")
    ).toBe(false);
    expect(isAccessingProtectedTable("x'; DROP TABLE reviews; --")).toBe(false);
  });
});

describe("stripFlagValues (response sanitizer)", () => {
  it("removes flag values but keeps the row's other columns", () => {
    expect(
      stripFlagValues([{ id: "1", leaked: "OSS{s0m3_fl4g}", name: "Bread" }])
    ).toEqual([{ id: "1", name: "Bread" }]);
  });

  it("keeps schema enumeration readable", () => {
    const tables = "reviews,flags,hints,internal_secrets";
    expect(stripFlagValues([{ userAgent: tables }])).toEqual([
      { userAgent: tables },
    ]);
  });

  it("drops a row that carried nothing but a flag value", () => {
    expect(stripFlagValues([{ leaked: "OSS{s0m3_fl4g}" }])).toEqual([]);
  });
});
