import {
  loginOrFail,
  TEST_USERS,
  expectFlag,
  getFirstProductId,
  uploadImage,
  createSvgFile,
  createJpegFile,
  UploadResponse,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Malicious File Upload (API)", () => {
  describe("SVG with script tag returns flag", () => {
    it("POST with SVG containing <script> returns 200 and flag", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const svg =
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('XSS')</script></svg>";
      const { status, data } = await uploadImage(
        token,
        productId,
        createSvgFile(svg)
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("flag", FLAGS.MALICIOUS_FILE_UPLOAD_XSS);
    });
  });

  describe("SVG with onload event handler returns flag", () => {
    it("POST with SVG containing onload returns 200 and flag", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const svg =
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'XSS\')"><rect width="100" height="100"/></svg>';
      const { status, data } = await uploadImage(
        token,
        productId,
        createSvgFile(svg)
      );

      expect(status).toBe(200);
      expectFlag(data, FLAGS.MALICIOUS_FILE_UPLOAD_XSS);
    });
  });

  describe("SVG with onerror returns flag", () => {
    it("POST with SVG containing onerror returns 200 and flag", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const svg =
        '<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>';
      const { status, data } = await uploadImage(
        token,
        productId,
        createSvgFile(svg)
      );

      expect(status).toBe(200);
      expectFlag(data, FLAGS.MALICIOUS_FILE_UPLOAD_XSS);
    });
  });

  describe("Clean SVG does NOT return flag", () => {
    it("POST with clean SVG returns 200 with imageUrl and no flag", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const svg =
        '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="blue"/></svg>';
      const { status, data } = await uploadImage(
        token,
        productId,
        createSvgFile(svg)
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("flag");
      expect(data).toHaveProperty("imageUrl");
    });
  });

  describe("Non-SVG image upload does not check for malicious content", () => {
    it("POST with valid JPEG returns 200 and does NOT return flag", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const { status, data } = await uploadImage(
        token,
        productId,
        createJpegFile()
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("flag");
    });
  });

  describe("Non-admin cannot upload", () => {
    it("POST as alice returns 403", async () => {
      const token = await loginOrFail(
        TEST_USERS.alice.email,
        TEST_USERS.alice.password
      );

      const productId = await getFirstProductId();
      const svg =
        '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100"/></svg>';
      const { status } = await uploadImage(
        token,
        productId,
        createSvgFile(svg)
      );

      expect(status).toBe(403);
    });
  });

  describe("File size limit enforced", () => {
    it("POST with file > 5MB returns 400 and error message", async () => {
      const token = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const productId = await getFirstProductId();
      const fiveMB = 5 * 1024 * 1024;
      const bigFile = new File([Buffer.alloc(fiveMB + 1)], "large.jpg", {
        type: "image/jpeg",
      });

      const { status, data } = await uploadImage(token, productId, bigFile);

      expect(status).toBe(400);
      expect(data).toHaveProperty("error");
      expect((data as UploadResponse).error).toMatch(
        /File size exceeds 5MB limit/i
      );
    });
  });
});
