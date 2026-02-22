import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface ExportErrorResponse {
  error?: string;
  debug?: {
    systemDiagnostics?: {
      nodeVersion?: string;
      environment?: string;
      database?: unknown;
      featureFlags?: string;
    };
  };
}

interface ExportSuccessResponse {
  data?: { email?: string; role?: string };
}

describe("Information Disclosure via API Error", () => {
  describe("Invalid export field triggers diagnostics leak with flag", () => {
    it("POST /api/user/export with invalid field returns 400 and leaks flag in debug.systemDiagnostics", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const { status, data } = await apiRequest<ExportErrorResponse>(
        "/api/user/export",
        {
          method: "POST",
          headers: authHeaders(token),
          body: JSON.stringify({ format: "json", fields: "invalid_field" }),
        }
      );

      expect(status).toBe(400);
      expect(data).toHaveProperty("debug");
      const debug = (data as ExportErrorResponse).debug;
      expect(debug).toHaveProperty("systemDiagnostics");
      expect(debug?.systemDiagnostics).toBeDefined();
      expect(debug?.systemDiagnostics?.featureFlags).toBe(
        FLAGS.INFORMATION_DISCLOSURE_API_ERROR
      );
      expect(debug?.systemDiagnostics).toHaveProperty("nodeVersion");
      expect(debug?.systemDiagnostics).toHaveProperty("environment");
      expect(debug?.systemDiagnostics).toHaveProperty("database");
    });
  });

  describe("Valid export does NOT leak diagnostics", () => {
    it("POST /api/user/export with valid fields returns 200 and no debug data", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const { status, data } = await apiRequest<ExportSuccessResponse>(
        "/api/user/export",
        {
          method: "POST",
          headers: authHeaders(token),
          body: JSON.stringify({ format: "json", fields: "email,role" }),
        }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("data");
      expect((data as ExportSuccessResponse).data).toHaveProperty("email");
      expect((data as ExportSuccessResponse).data).toHaveProperty("role");
      const bodyStr = JSON.stringify(data);
      expect(bodyStr).not.toMatch(/debug|systemDiagnostics/);
    });
  });

  describe("CSV export format works", () => {
    it("POST /api/user/export with format csv returns 200 and Content-Type text/csv", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const { status, headers } = await apiRequest("/api/user/export", {
        method: "POST",
        headers: authHeaders(token),
        body: JSON.stringify({ format: "csv", fields: "email,role" }),
      });

      expect(status).toBe(200);
      expect(headers.get("Content-Type")).toMatch(/text\/csv/);
    });
  });

  describe("Missing format/fields returns 400", () => {
    it("POST /api/user/export with empty body returns 400 and mentions missing required fields", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const { status, data } = await apiRequest<{ error?: string }>(
        "/api/user/export",
        {
          method: "POST",
          headers: authHeaders(token),
          body: JSON.stringify({}),
        }
      );

      expect(status).toBe(400);
      expect((data as { error?: string }).error).toMatch(
        /Missing required fields/i
      );
    });
  });

  describe("Unauthenticated request is rejected", () => {
    it("POST /api/user/export without auth returns 401", async () => {
      const { status } = await apiRequest("/api/user/export", {
        method: "POST",
        body: JSON.stringify({ format: "json", fields: "email,role" }),
      });

      expect(status).toBe(401);
    });
  });
});
