import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("React 19 RCE (CVE-2025-55182) – react2shell", () => {
  it("POST /api/flags/verify returns valid: true for OSS{r3act2sh3ll}", async () => {
    const { status, data } = await apiRequest<{ valid: boolean }>(
      "/api/flags/verify",
      {
        method: "POST",
        body: JSON.stringify({ flag: FLAGS.REACT2SHELL }),
      }
    );

    expect(status).toBe(200);
    expect(data).toHaveProperty("valid", true);
  });
});
