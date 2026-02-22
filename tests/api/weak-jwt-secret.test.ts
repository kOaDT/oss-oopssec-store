import { createWeakJWT, decodeWeakJWT, hashMD5 } from "../../lib/server-auth";
import { loginOrFail, TEST_USERS } from "../helpers/api";
import { decodeJwtPayload } from "../helpers/unit";

describe("Weak JWT Secret (server-auth)", () => {
  it("JWT contains hint in payload", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const payload = decodeJwtPayload(token);
    expect(payload).toHaveProperty("hint", "The secret is not so secret");
  });

  it("JWT can be forged with known secret", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const decoded = decodeWeakJWT(token);
    expect(decoded).not.toBeNull();
    const aliceId = decoded!.id;
    const aliceEmail = decoded!.email;

    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const forgedToken = createWeakJWT({
      id: aliceId,
      email: aliceEmail,
      role: "ADMIN",
      exp: futureExp,
    });

    const forgedDecoded = decodeWeakJWT(forgedToken);
    expect(forgedDecoded).not.toBeNull();
    expect(forgedDecoded!.role).toBe("ADMIN");
  });

  it("hashMD5 produces expected hashes", () => {
    expect(hashMD5("admin")).toBe("21232f297a57a5a743894a0e4a801fc3");
    const iloveduckHash = hashMD5("iloveduck");
    expect(iloveduckHash).toMatch(/^[a-f0-9]{32}$/);
  });
});
