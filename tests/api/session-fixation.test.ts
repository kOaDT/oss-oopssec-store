import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
  extractAuthTokenFromHeaders,
  BASE_URL,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Session Fixation / Weak Session Management (API)", () => {
  it("creates support token for admin email as regular user", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status, data } = await apiRequest<{
      supportToken?: { token: string };
      supportLoginUrl?: string;
    }>("/api/user/support-access", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ email: "admin@oss.com" }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("supportToken");
    expect(data.supportToken).toHaveProperty("token");
    expect(data).toHaveProperty("supportLoginUrl");
    expect((data as { supportLoginUrl: string }).supportLoginUrl).toMatch(
      /\/support-login\?token=.+/
    );
  });

  it("login via support token grants admin access with flag", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const createRes = await apiRequest<{
      supportToken: { token: string };
      supportLoginUrl: string;
    }>("/api/user/support-access", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ email: "admin@oss.com" }),
    });
    expect(createRes.status).toBe(200);
    const supportTokenValue = createRes.data.supportToken.token;

    const supportLoginRes = await fetch(
      `${BASE_URL}/api/auth/support-login?token=${supportTokenValue}`,
      { method: "GET", redirect: "manual" }
    );
    expect([200, 302]).toContain(supportLoginRes.status);

    const authToken = extractAuthTokenFromHeaders(supportLoginRes.headers);
    expect(authToken).not.toBeNull();

    const { status, data } = await apiRequest<{ flag?: string }>("/api/admin", {
      headers: authHeaders(authToken!),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.SESSION_FIXATION);
  });

  it("support token for own email works normally", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status, data } = await apiRequest<{
      supportToken?: { token: string };
      supportLoginUrl?: string;
    }>("/api/user/support-access", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ email: "alice@example.com" }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("supportToken");
    expect(data.supportToken).toHaveProperty("token");
    expect((data.supportToken as { token: string }).token).toBeTruthy();
  });

  it("unauthenticated request is rejected", async () => {
    const { status } = await apiRequest("/api/user/support-access", {
      method: "POST",
      body: JSON.stringify({ email: "admin@oss.com" }),
    });

    expect(status).toBe(401);
  });

  it("non-existent email is rejected", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/user/support-access", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ email: "nonexistent@example.com" }),
    });

    expect(status).toBe(404);
  });
});
