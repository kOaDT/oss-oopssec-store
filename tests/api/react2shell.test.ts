import { apiRequest, BASE_URL } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

/**
 * The RCE itself is never fired in CI. This suite checks that the running
 * server still exposes what the exploit needs — a Flight endpoint that serves
 * client references, and a Server Action pipeline that deserializes a
 * client-supplied reference id before it validates it — while
 * tests/unit/react2shell-flight-deserializer.test.ts covers the unguarded
 * prototype-chain lookups those references are resolved with.
 */

const CLIENT_REFERENCE_ROW = /^\d+:I\[.*\]$/m;
const UNVALIDATED_REFERENCE_ID = "reference-that-no-manifest-declares";

async function postForm(fields: Record<string, string>): Promise<number> {
  const body = new FormData();
  for (const [name, value] of Object.entries(fields)) {
    body.append(name, value);
  }

  const response = await fetch(BASE_URL, { method: "POST", body });
  return response.status;
}

describe("React 19 RCE (CVE-2025-55182) – react2shell", () => {
  it("serves client references over the Flight protocol", async () => {
    const response = await fetch(BASE_URL, { headers: { RSC: "1" } });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/x-component");
    expect(await response.text()).toMatch(CLIENT_REFERENCE_ROW);
  });

  it("deserializes an unauthenticated Server Action reference id", async () => {
    expect(await postForm({ plainField: "value" })).toBe(200);
    expect(
      await postForm({ [`$ACTION_ID_${UNVALIDATED_REFERENCE_ID}`]: "1" })
    ).toBe(500);
  });

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
