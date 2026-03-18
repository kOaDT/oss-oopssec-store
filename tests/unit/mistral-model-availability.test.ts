/**
 * Validates that the Mistral model used by the AI assistant route
 * is still available via the Mistral API.
 *
 * Requires MISTRAL_API_KEY env var — skipped when absent (e.g. fork PRs).
 */

const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY;

// Must match the model in app/api/ai-assistant/route.ts
const EXPECTED_MODEL = "mistral-small-2603";

const describeIfKey = MISTRAL_API_KEY ? describe : describe.skip;

describeIfKey("Mistral model availability", () => {
  let data: Record<string, unknown>;

  beforeAll(async () => {
    const response = await fetch(
      `https://api.mistral.ai/v1/models/${EXPECTED_MODEL}`,
      {
        headers: { Authorization: `Bearer ${MISTRAL_API_KEY}` },
      }
    );

    expect(response.status).toBe(200);
    data = await response.json();
  });

  it(`model "${EXPECTED_MODEL}" should exist`, () => {
    expect(data.id).toBe(EXPECTED_MODEL);
  });

  it("should not be deprecated", () => {
    expect(data.deprecation).toBeNull();
  });

  it("should support chat completion", () => {
    expect((data.capabilities as Record<string, boolean>).completion_chat).toBe(
      true
    );
  });

  it("should support function calling", () => {
    expect(
      (data.capabilities as Record<string, boolean>).function_calling
    ).toBe(true);
  });
});
