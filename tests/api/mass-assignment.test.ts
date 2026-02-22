import {
  apiRequest,
  authHeaders,
  TEST_USERS,
  expectFlag,
  extractAuthTokenFromHeaders,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Mass Assignment (API)", () => {
  it("signup with role ADMIN creates admin account", async () => {
    const email = `attacker-mass-${Date.now()}@evil.com`;
    const { status, data, headers } = await apiRequest<{
      user?: { id: string; email: string; role: string };
    }>("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({
        email,
        password: "password123",
        role: "ADMIN",
      }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("user");
    expect((data as { user: { role: string } }).user.role).toBe("ADMIN");

    const token = extractAuthTokenFromHeaders(headers);
    expect(token).not.toBeNull();
  });

  it("new admin account triggers mass assignment flag", async () => {
    const email = `attacker-mass-${Date.now()}@evil.com`;
    const {
      status: signupStatus,
      data: signupData,
      headers,
    } = await apiRequest<{
      user?: { id: string; email: string; role: string };
    }>("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({
        email,
        password: "password123",
        role: "ADMIN",
      }),
    });

    expect(signupStatus).toBe(200);
    expect((signupData as { user: { role: string } }).user.role).toBe("ADMIN");

    const token = extractAuthTokenFromHeaders(headers);
    expect(token).not.toBeNull();

    const { status, data } = await apiRequest<{ flag?: string }>("/api/admin", {
      headers: authHeaders(token!),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.MASS_ASSIGNMENT);
  });

  it("normal signup without role creates CUSTOMER", async () => {
    const email = `normal-user-${Date.now()}@example.com`;
    const { status, data } = await apiRequest<{
      user?: { id: string; email: string; role: string };
    }>("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({
        email,
        password: "password123",
      }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("user");
    expect((data as { user: { role: string } }).user.role).toBe("CUSTOMER");
  });

  it("duplicate email is rejected", async () => {
    const { status } = await apiRequest("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({
        email: TEST_USERS.alice.email,
        password: "test",
      }),
    });

    expect(status).toBe(409);
  });
});
