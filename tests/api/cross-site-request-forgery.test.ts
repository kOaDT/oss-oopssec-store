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

/** What a browser attaches when a page fires the request, unlike a CLI client. */
const firedByPage = (referer: string) => ({
  Referer: referer,
  "Sec-Fetch-Site": "same-origin",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});

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

  it("returns the flag when the attacker page fires the request", async () => {
    const { status, data } = await updateStatus(
      "SHIPPED",
      firedByPage(EXPLOIT_PAGE)
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
    expect(data.order.status).toBe("SHIPPED");
  });

  it("returns the flag for a form-encoded POST from the attacker page", async () => {
    const { status, data } = await apiRequest<UpdateResponse>(
      `/api/orders/${ORDER_ID}`,
      {
        method: "POST",
        headers: {
          ...authHeaders(adminToken),
          ...firedByPage(EXPLOIT_PAGE),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "status=CANCELLED",
      }
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
  });

  it("does not reward a request no page ever fired", async () => {
    const { status, data } = await updateStatus("DELIVERED");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("nothing says a page fired this request");
  });

  it("still updates the order without any anti-CSRF check, flag or not", async () => {
    const { data } = await updateStatus("PROCESSING");

    expect(data.success).toBe(true);
    expect(data.order.status).toBe("PROCESSING");
  });

  it("does not reward the admin dashboard doing its own job", async () => {
    const { status, data } = await updateStatus(
      "PENDING",
      firedByPage("http://localhost:3000/admin/orders")
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
      headers: { ...authHeaders(token), ...firedByPage(EXPLOIT_PAGE) },
      body: JSON.stringify({ status: "SHIPPED" }),
    });

    expect(status).toBe(403);
  });

  it("rejects an invalid status", async () => {
    const { status } = await updateStatus("INVALID", firedByPage(EXPLOIT_PAGE));

    expect(status).toBe(400);
  });
});
