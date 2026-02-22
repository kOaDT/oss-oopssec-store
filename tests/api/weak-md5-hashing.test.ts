import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
  BASE_URL,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Weak MD5 Hashing (API)", () => {
  it("admin login + admin endpoint returns MD5 flag", async () => {
    const response = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: TEST_USERS.admin.email,
        password: TEST_USERS.admin.password,
      }),
    });
    const loginData = (await response.json()) as {
      user?: { id: string; email: string; role: string };
      error?: string;
    };
    expect(response.status).toBe(200);
    expect(loginData.user?.role).toBe("ADMIN");

    const setCookie = response.headers.get("set-cookie");
    const match = setCookie?.match(/authToken=([^;]+)/);
    const token = match ? match[1] : null;
    expect(token).not.toBeNull();

    const { status, data } = await apiRequest<{ flag?: string }>("/api/admin", {
      headers: authHeaders(token!),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.WEAK_MD5_HASHING);
  });

  it("admin endpoint accessible after cracking MD5", async () => {
    // Chain: known hash 21232f297a57a5a743894a0e4a801fc3 → crack → "admin" → login → admin access
    const token = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const { status, data } = await apiRequest<{ flag?: string }>("/api/admin", {
      headers: authHeaders(token),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.WEAK_MD5_HASHING);
  });
});
