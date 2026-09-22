import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const ORDER_ID = "ORD-001";
const EXPLOIT_PAGE = "http://localhost:3000/exploits/csrf-attack.html";

interface UpdateResponse {
  success: boolean;
  order: { id: string; status: string };
  flag?: string;
  message?: string;
}

/**
 * The metadata a browser attaches on behalf of a page. Page JavaScript cannot
 * set these, but any CLI client can, which is how these tests drive the
 * scenario without a browser: the endpoint reads a shape, not a proof.
 */
const browserMetadata = (referer: string, site = "same-origin") => ({
  Referer: referer,
  "Sec-Fetch-Site": site,
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});

/** What a page carrying `<meta name="referrer" content="no-referrer">` sends. */
const secFetchWithoutReferer = {
  "Sec-Fetch-Site": "cross-site",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
};

describe("Cross-Site Request Forgery (CSRF)", () => {
  let adminToken: string;

  const updateStatus = (status: string, headers: Record<string, string> = {}) =>
    apiRequest<UpdateResponse>(`/api/orders/${ORDER_ID}`, {
      method: "PATCH",
      headers: { ...authHeaders(adminToken), ...headers },
      body: JSON.stringify({ status }),
    });

  beforeAll(async () => {
    adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );
  });

  it("returns the flag for a request shaped like one an attacker page fired", async () => {
    const { status, data } = await updateStatus(
      "SHIPPED",
      browserMetadata(EXPLOIT_PAGE)
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
    expect(data.order.status).toBe("SHIPPED");
  });

  it("returns the flag for a form-encoded POST shaped like the attacker page's", async () => {
    const { status, data } = await apiRequest<UpdateResponse>(
      `/api/orders/${ORDER_ID}`,
      {
        method: "POST",
        headers: {
          ...authHeaders(adminToken),
          ...browserMetadata(EXPLOIT_PAGE),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "status=CANCELLED",
      }
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
  });

  it("does not reward a request carrying no browser metadata", async () => {
    const { status, data } = await updateStatus("DELIVERED");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("carries none of the metadata");
  });

  it("does not reward a Referer that arrives without Sec-Fetch headers", async () => {
    const { status, data } = await updateStatus("DELIVERED", {
      Referer: EXPLOIT_PAGE,
    });

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("carries none of the metadata");
  });

  it("does not reward Sec-Fetch headers that arrive without a Referer", async () => {
    const { status, data } = await updateStatus(
      "DELIVERED",
      secFetchWithoutReferer
    );

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("carries none of the metadata");
  });

  it("returns the flag for a page served from another origin", async () => {
    const { status, data } = await updateStatus(
      "SHIPPED",
      browserMetadata("https://evil.com/attack", "cross-site")
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
  });

  it("still updates the order without any anti-CSRF check, flag or not", async () => {
    const { data } = await updateStatus("PROCESSING");

    expect(data.success).toBe(true);
    expect(data.order.status).toBe("PROCESSING");
  });

  it("does not reward a Referer pointing at the admin dashboard", async () => {
    const { status, data } = await updateStatus(
      "PENDING",
      browserMetadata("http://localhost:3000/admin/orders")
    );

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data).not.toHaveProperty("message");
  });

  it("refuses a non-admin", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest(`/api/orders/${ORDER_ID}`, {
      method: "PATCH",
      headers: { ...authHeaders(token), ...browserMetadata(EXPLOIT_PAGE) },
      body: JSON.stringify({ status: "SHIPPED" }),
    });

    expect(status).toBe(403);
  });

  it("rejects an invalid status", async () => {
    const { status } = await updateStatus(
      "INVALID",
      browserMetadata(EXPLOIT_PAGE)
    );

    expect(status).toBe(400);
  });
});
