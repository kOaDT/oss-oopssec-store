import { apiRequest, TEST_USERS, waitForCondition } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const BASIC_AUTH_ROOT_ADMIN = "Basic cm9vdDphZG1pbg==";
const BASIC_AUTH_WRONG = "Basic d3Jvbmc6Y3JlZHM=";

interface LogEntry {
  timestamp?: string;
  level?: string;
  message?: string;
}

interface LogsResponse {
  logs?: LogEntry[];
  error?: string;
}

describe("Plaintext Password in Logs", () => {
  describe("Login triggers log entry with plaintext password", () => {
    it("POST /api/auth/login logs credentials; GET /api/monitoring/logs with Basic auth returns logs containing password and flag", async () => {
      await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: TEST_USERS.alice.email,
          password: "iloveduck",
        }),
      });

      // Poll until the log entry appears (avoids flaky timing)
      await waitForCondition(
        () =>
          apiRequest<LogsResponse>("/api/monitoring/logs", {
            method: "GET",
            headers: { Authorization: BASIC_AUTH_ROOT_ADMIN },
          }),
        (res) =>
          ((res.data as LogsResponse).logs ?? []).some((e) =>
            e.message?.includes("iloveduck")
          )
      );

      const { status, data } = await apiRequest<LogsResponse>(
        "/api/monitoring/logs",
        {
          method: "GET",
          headers: { Authorization: BASIC_AUTH_ROOT_ADMIN },
        }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("logs");
      const logs = (data as LogsResponse).logs;
      expect(Array.isArray(logs)).toBe(true);

      const loginLog = logs?.find(
        (entry) =>
          entry.message?.includes("iloveduck") ||
          entry.message?.includes("[auth] login attempt")
      );
      expect(loginLog).toBeDefined();
      expect(loginLog?.message).toContain("iloveduck");
      expect(loginLog?.message).toContain(FLAGS.PLAINTEXT_PASSWORD_IN_LOGS);
    });
  });

  describe("Monitoring endpoint requires authentication", () => {
    it("GET /api/monitoring/logs without auth returns 401", async () => {
      const { status } = await apiRequest<LogsResponse>(
        "/api/monitoring/logs",
        { method: "GET" }
      );
      expect(status).toBe(401);
    });
  });

  describe("Monitoring endpoint rejects wrong credentials", () => {
    it("GET /api/monitoring/logs with wrong Basic auth returns 401", async () => {
      const { status } = await apiRequest<LogsResponse>(
        "/api/monitoring/logs",
        {
          method: "GET",
          headers: { Authorization: BASIC_AUTH_WRONG },
        }
      );
      expect(status).toBe(401);
    });
  });

  describe("Monitoring endpoint accepts siem_session cookie", () => {
    it("GET /api/monitoring/logs with siem_session=authenticated returns 200 and logs", async () => {
      const { status, data } = await apiRequest<LogsResponse>(
        "/api/monitoring/logs",
        {
          method: "GET",
          headers: { Cookie: "siem_session=authenticated" },
        }
      );
      expect(status).toBe(200);
      expect(data).toHaveProperty("logs");
    });
  });

  describe("Multiple login attempts all logged", () => {
    it("several login attempts appear in logs with plaintext passwords", async () => {
      const attempts = [
        { email: TEST_USERS.alice.email, password: "iloveduck" },
        { email: TEST_USERS.bob.email, password: "qwerty" },
        { email: TEST_USERS.admin.email, password: "admin" },
      ];

      for (const { email, password } of attempts) {
        await apiRequest("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
      }

      await waitForCondition(
        () =>
          apiRequest<LogsResponse>("/api/monitoring/logs", {
            method: "GET",
            headers: { Authorization: BASIC_AUTH_ROOT_ADMIN },
          }),
        (res) => {
          const msgs = ((res.data as LogsResponse).logs ?? [])
            .map((e) => e.message ?? "")
            .join(" ");
          return (
            msgs.includes("iloveduck") &&
            msgs.includes("qwerty") &&
            msgs.includes("admin")
          );
        }
      );

      const { status, data } = await apiRequest<LogsResponse>(
        "/api/monitoring/logs",
        {
          method: "GET",
          headers: { Authorization: BASIC_AUTH_ROOT_ADMIN },
        }
      );

      expect(status).toBe(200);
      const logs = (data as LogsResponse).logs ?? [];
      const messages = logs.map((e) => e.message ?? "").join(" ");

      expect(messages).toContain("iloveduck");
      expect(messages).toContain("qwerty");
      expect(messages).toContain("admin");
    });
  });
});
