import { createWeakJWT, decodeWeakJWT } from "../../lib/server-auth";

describe("JWT (createWeakJWT / decodeWeakJWT)", () => {
  const validPayload = {
    id: "user-1",
    email: "test@example.com",
    role: "CUSTOMER",
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  it("creates a valid JWT with 3 dot-separated parts", () => {
    const token = createWeakJWT(validPayload);
    const parts = token.split(".");

    expect(parts).toHaveLength(3);
    parts.forEach((part) => expect(part.length).toBeGreaterThan(0));
  });

  it("encodes header as HS256 JWT", () => {
    const token = createWeakJWT(validPayload);
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64url").toString()
    );

    expect(header).toEqual({ alg: "HS256", typ: "JWT" });
  });

  it("roundtrips: decode(create(payload)) returns the original payload", () => {
    const token = createWeakJWT(validPayload);
    const decoded = decodeWeakJWT(token);

    expect(decoded).not.toBeNull();
    expect(decoded!.id).toBe(validPayload.id);
    expect(decoded!.email).toBe(validPayload.email);
    expect(decoded!.role).toBe(validPayload.role);
    expect(decoded!.exp).toBe(validPayload.exp);
  });

  it("returns null for expired token", () => {
    const expiredPayload = {
      ...validPayload,
      exp: Math.floor(Date.now() / 1000) - 100,
    };
    const token = createWeakJWT(expiredPayload);

    expect(decodeWeakJWT(token)).toBeNull();
  });

  it("returns null for tampered payload", () => {
    const token = createWeakJWT(validPayload);
    const [header, , signature] = token.split(".");

    const tamperedBody = Buffer.from(
      JSON.stringify({ ...validPayload, role: "ADMIN" })
    ).toString("base64url");

    expect(decodeWeakJWT(`${header}.${tamperedBody}.${signature}`)).toBeNull();
  });

  it("returns null for tampered signature", () => {
    const token = createWeakJWT(validPayload);
    const [header, body] = token.split(".");

    expect(decodeWeakJWT(`${header}.${body}.invalidsignature`)).toBeNull();
  });

  it("returns null for malformed tokens", () => {
    expect(decodeWeakJWT("")).toBeNull();
    expect(decodeWeakJWT("onlyonepart")).toBeNull();
    expect(decodeWeakJWT("two.parts")).toBeNull();
    expect(decodeWeakJWT("a.b.c.d")).toBeNull();
  });

  it("returns null for invalid base64 body", () => {
    const token = createWeakJWT(validPayload);
    const [header, , signature] = token.split(".");

    expect(decodeWeakJWT(`${header}.!!!invalid!!!.${signature}`)).toBeNull();
  });

  it("preserves optional supportAccess field", () => {
    const payloadWithSupport = { ...validPayload, supportAccess: true };
    const token = createWeakJWT(payloadWithSupport);
    const decoded = decodeWeakJWT(token);

    expect(decoded).not.toBeNull();
    expect(decoded!.supportAccess).toBe(true);
  });
});
