import { hashMD5 } from "../../lib/server-auth";

describe("Weak MD5 Hashing (server-auth)", () => {
  it("MD5 hash of 'admin' matches known value", () => {
    expect(hashMD5("admin")).toBe("21232f297a57a5a743894a0e4a801fc3");
  });

  it("MD5 hash of common passwords produces known hashes", () => {
    expect(hashMD5("qwerty")).toBe("d8578edf8458ce06fbc5bb76a58c5ca4");
    expect(hashMD5("sunshine")).toBe("0571749e2ac330a7455809c6b0e7af90");
    const iloveduckHash = hashMD5("iloveduck");
    expect(iloveduckHash).toMatch(/^[a-f0-9]{32}$/);
  });
});
