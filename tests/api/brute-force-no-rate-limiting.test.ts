import { apiRequest, TEST_USERS, expectFlag } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

async function loginAttempt(email: string, password: string) {
  return apiRequest<{ flag?: string | null }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

describe("Brute Force / No Rate Limiting (API)", () => {
  it("multiple failed login attempts are not rate-limited", async () => {
    const attempts = Array.from({ length: 10 }, () =>
      loginAttempt(TEST_USERS.bruteForce.email, "wrong")
    );
    const results = await Promise.all(attempts);

    for (const { status } of results) {
      expect(status).toBe(401);
    }
  });

  it("successful login after brute force returns flag", async () => {
    await loginAttempt(TEST_USERS.bruteForce.email, "wrong1");
    await loginAttempt(TEST_USERS.bruteForce.email, "wrong2");

    const { status, data } = await loginAttempt(
      TEST_USERS.bruteForce.email,
      TEST_USERS.bruteForce.password
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.BRUTE_FORCE_NO_RATE_LIMIT);
  });

  it("brute force simulation with common passwords", async () => {
    const commonPasswords = [
      "123456",
      "password",
      "qwerty",
      "abc123",
      "sunshine",
    ];

    for (let i = 0; i < commonPasswords.length - 1; i++) {
      const { status } = await loginAttempt(
        TEST_USERS.bruteForce.email,
        commonPasswords[i]
      );
      expect(status).toBe(401);
    }

    const { status, data } = await loginAttempt(
      TEST_USERS.bruteForce.email,
      commonPasswords[commonPasswords.length - 1]
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.BRUTE_FORCE_NO_RATE_LIMIT);
  });

  it("other users login does NOT return brute force flag", async () => {
    const { status, data } = await loginAttempt(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    expect(status).toBe(200);
    expect(data).toHaveProperty("flag", null);
  });
});
