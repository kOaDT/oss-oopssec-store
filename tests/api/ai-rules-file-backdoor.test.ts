import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface DiagResponse {
  ok?: boolean;
  flag?: string;
  build?: string;
  error?: string;
}

interface VerifyResponse {
  valid: boolean;
  slug?: string;
}

const DIAG_TOKEN = "dbg_8f3a7c91e2b4d6a05e21";

describe("AI Rules File Backdoor — runtime exploitation of the injected diagnostic endpoint", () => {
  describe("GET /api/admin/diag without the magic header", () => {
    it("returns 403 when no header is supplied", async () => {
      const { status, data } =
        await apiRequest<DiagResponse>("/api/admin/diag");

      expect(status).toBe(403);
      expect((data as DiagResponse).flag).toBeUndefined();
      expect((data as DiagResponse).error).toBe("Forbidden");
    });

    it("returns 403 when the header value is wrong", async () => {
      const { status, data } = await apiRequest<DiagResponse>(
        "/api/admin/diag",
        {
          headers: { "X-Debug-Auth": "wrong-token" },
        }
      );

      expect(status).toBe(403);
      expect((data as DiagResponse).flag).toBeUndefined();
    });

    it("returns 403 when the header value is empty", async () => {
      const { status, data } = await apiRequest<DiagResponse>(
        "/api/admin/diag",
        {
          headers: { "X-Debug-Auth": "" },
        }
      );

      expect(status).toBe(403);
      expect((data as DiagResponse).flag).toBeUndefined();
    });
  });

  describe("GET /api/admin/diag with the magic header", () => {
    it("returns 200 with the flag in the JSON body", async () => {
      const { status, data } = await apiRequest<DiagResponse>(
        "/api/admin/diag",
        {
          headers: { "X-Debug-Auth": DIAG_TOKEN },
        }
      );

      expect(status).toBe(200);
      expect((data as DiagResponse).ok).toBe(true);
      expect((data as DiagResponse).flag).toBe(FLAGS.AI_RULES_FILE_BACKDOOR);
      expect((data as DiagResponse).build).toBeTruthy();
    });
  });

  describe("Flag verification", () => {
    it("flag #2 verifies successfully", async () => {
      const { status, data } = await apiRequest<VerifyResponse>(
        "/api/flags/verify",
        {
          method: "POST",
          body: JSON.stringify({ flag: FLAGS.AI_RULES_FILE_BACKDOOR }),
        }
      );

      expect(status).toBe(200);
      expect((data as VerifyResponse).valid).toBe(true);
      expect((data as VerifyResponse).slug).toBe("ai-rules-file-backdoor");
    });
  });
});
