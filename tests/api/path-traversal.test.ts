import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface FileResponse {
  filename?: string;
  content?: string;
  error?: string;
}

interface ListResponse {
  path?: string;
  items?: Array<{ name: string; type: string; size: number; modified: string }>;
}

describe("Path Traversal", () => {
  describe("Path traversal reads flag.txt", () => {
    it("GET /api/files?file=../flag.txt returns 200 and content contains the flag", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=../flag.txt"
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("content");
      expect((data as FileResponse).content).toContain(FLAGS.PATH_TRAVERSAL);
    });
  });

  describe("Normal file access within documents/ works", () => {
    it("GET /api/files?file=readme.txt returns 200 with filename and content", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=readme.txt"
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("filename");
      expect(data).toHaveProperty("content");
    });
  });

  describe("Directory listing works", () => {
    it("GET /api/files?list=true returns 200 and items array", async () => {
      const { status, data } = await apiRequest<ListResponse>(
        "/api/files?list=true"
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("items");
      expect(Array.isArray((data as ListResponse).items)).toBe(true);
    });
  });

  describe("Missing file parameter returns 400", () => {
    it("GET /api/files without params returns 400 and error message", async () => {
      const { status, data } = await apiRequest<{ error?: string }>(
        "/api/files"
      );

      expect(status).toBe(400);
      expect(data).toHaveProperty("error");
      expect((data as { error?: string }).error).toMatch(
        /file parameter is required/i
      );
    });
  });

  describe("Non-existent file returns 500", () => {
    it("GET /api/files?file=nonexistent.txt returns 500", async () => {
      const { status } = await apiRequest("/api/files?file=nonexistent.txt");

      expect(status).toBe(500);
    });
  });

  describe("Multiple levels of traversal", () => {
    it("GET /api/files?file=../../etc/passwd does not crash the server", async () => {
      const { status } = await apiRequest("/api/files?file=../../etc/passwd");

      expect([200, 500]).toContain(status);
    });
  });
});
