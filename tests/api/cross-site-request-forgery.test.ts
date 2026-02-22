import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const ORDER_ID = "ORD-001";

describe("Cross-Site Request Forgery (CSRF)", () => {
  describe("Status update without admin referer returns CSRF flag", () => {
    it("returns 200 and flag when Referer is evil origin", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest<{ flag?: string }>(
        `/api/orders/${ORDER_ID}`,
        {
          method: "PATCH",
          headers: {
            ...authHeaders(token),
            Referer: "https://evil.com/attack",
          },
          body: JSON.stringify({ status: "SHIPPED" }),
        }
      );

      expect(status).toBe(200);
      expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
    });
  });

  describe("Status update from admin dashboard does NOT return flag", () => {
    it("returns 200 without flag when Referer contains /admin", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest<{ flag?: string }>(
        `/api/orders/${ORDER_ID}`,
        {
          method: "PATCH",
          headers: {
            ...authHeaders(token),
            Referer: "http://localhost:3000/admin/orders",
          },
          body: JSON.stringify({ status: "PROCESSING" }),
        }
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("flag");
    });
  });

  describe("Status update with no referer returns flag", () => {
    it("returns 200 and flag when Referer is absent", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest<{ flag?: string }>(
        `/api/orders/${ORDER_ID}`,
        {
          method: "PATCH",
          headers: authHeaders(token),
          body: JSON.stringify({ status: "DELIVERED" }),
        }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("flag", FLAGS.CROSS_SITE_REQUEST_FORGERY);
    });
  });

  describe("Form-encoded POST also works (CSRF simulation)", () => {
    it("returns 200 and flag for form-encoded POST with evil Referer", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest<{ flag?: string }>(
        `/api/orders/${ORDER_ID}`,
        {
          method: "POST",
          headers: {
            ...authHeaders(token),
            "Content-Type": "application/x-www-form-urlencoded",
            Referer: "https://evil.com",
          },
          body: "status=CANCELLED",
        }
      );

      expect(status).toBe(200);
      expectFlag(data, FLAGS.CROSS_SITE_REQUEST_FORGERY);
    });
  });

  describe("Non-admin cannot update order status", () => {
    it("returns 403 when non-admin patches order", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const { status } = await apiRequest(`/api/orders/${ORDER_ID}`, {
        method: "PATCH",
        headers: authHeaders(token),
        body: JSON.stringify({ status: "SHIPPED" }),
      });

      expect(status).toBe(403);
    });
  });

  describe("Invalid status is rejected", () => {
    it("returns 400 when status is invalid", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status } = await apiRequest(`/api/orders/${ORDER_ID}`, {
        method: "PATCH",
        headers: authHeaders(token),
        body: JSON.stringify({ status: "INVALID" }),
      });

      expect(status).toBe(400);
    });
  });
});
