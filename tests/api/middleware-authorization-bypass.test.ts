import { loginOrFail, authHeaders, TEST_USERS, BASE_URL } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const INTERNAL_STATUS_URL = `${BASE_URL}/monitoring/internal-status`;
const BYPASS_HEADER = "middleware:middleware:middleware:middleware:middleware";

describe("Middleware Authorization Bypass (CVE-2025-29927)", () => {
  it("redirects unauthenticated users to /login", async () => {
    const response = await fetch(INTERNAL_STATUS_URL, {
      redirect: "manual",
    });

    expect(response.status).toBe(307);
    const location = response.headers.get("location");
    expect(location).toContain("/login");
  });

  it("redirects non-admin authenticated users to /login", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const response = await fetch(INTERNAL_STATUS_URL, {
      headers: authHeaders(token),
      redirect: "manual",
    });

    expect(response.status).toBe(307);
    const location = response.headers.get("location");
    expect(location).toContain("/login");
  });

  it("allows authenticated admin users to access the page", async () => {
    const token = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const response = await fetch(INTERNAL_STATUS_URL, {
      headers: {
        ...authHeaders(token),
      },
    });

    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain("Internal Status");
  });

  it("bypasses middleware with x-middleware-subrequest header (CVE-2025-29927)", async () => {
    const response = await fetch(INTERNAL_STATUS_URL, {
      headers: {
        "x-middleware-subrequest": BYPASS_HEADER,
      },
    });

    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain(FLAGS.MIDDLEWARE_AUTHORIZATION_BYPASS);
  });

  it("does not bypass with a single middleware value", async () => {
    const response = await fetch(INTERNAL_STATUS_URL, {
      headers: {
        "x-middleware-subrequest": "middleware",
      },
      redirect: "manual",
    });

    expect(response.status).toBe(307);
    const location = response.headers.get("location");
    expect(location).toContain("/login");
  });
});
