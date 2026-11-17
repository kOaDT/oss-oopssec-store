import {
  DEFAULT_LLM_BASE_URL,
  DEFAULT_LLM_MODEL,
  llmFailure,
  providerErrorMessage,
  resolveLlmConfig,
} from "../../lib/llm";

describe("resolveLlmConfig", () => {
  it("targets a local Ollama model when nothing is configured", () => {
    expect(resolveLlmConfig({})).toEqual({
      baseUrl: DEFAULT_LLM_BASE_URL,
      model: DEFAULT_LLM_MODEL,
      apiKey: undefined,
    });
  });

  it("treats empty or blank values as unset", () => {
    expect(
      resolveLlmConfig({ LLM_BASE_URL: "", LLM_MODEL: " ", LLM_API_KEY: "" })
    ).toEqual(resolveLlmConfig({}));
  });

  it("uses the configured endpoint, model and key", () => {
    expect(
      resolveLlmConfig({
        LLM_BASE_URL: "https://api.mistral.ai/v1",
        LLM_MODEL: "mistral-small-2603",
        LLM_API_KEY: "sk-test",
      })
    ).toEqual({
      baseUrl: "https://api.mistral.ai/v1",
      model: "mistral-small-2603",
      apiKey: "sk-test",
    });
  });

  it("strips trailing slashes so the completions path joins cleanly", () => {
    expect(
      resolveLlmConfig({ LLM_BASE_URL: "http://ollama:11434/v1//" }).baseUrl
    ).toBe("http://ollama:11434/v1");
  });

  it.each([
    "localhost:11434/v1",
    "ftp://ollama/v1",
    '"http://ollama:11434/v1"',
  ])("rejects %s, naming the variable to fix", (value) => {
    expect(() => resolveLlmConfig({ LLM_BASE_URL: value })).toThrow(
      /LLM_BASE_URL must be an http\(s\) URL/
    );
  });
});

describe("llmFailure", () => {
  it.each([
    [401, "llm_unauthorized", 502],
    [403, "llm_unauthorized", 502],
    [429, "llm_rate_limited", 429],
    [500, "llm_failed", 502],
  ])("maps upstream %i to %s with status %i", (upstream, code, status) => {
    expect(llmFailure(upstream)).toMatchObject({ code, status });
  });

  it("reads Ollama's 404 for an unknown model as a missing model", () => {
    expect(llmFailure(404, "model 'gemma4:e4b' not found")).toMatchObject({
      code: "llm_model_not_found",
      status: 502,
    });
  });

  // Ollama answers a path without /v1 with a plain-text "404 page not found".
  it.each([undefined, "Not Found"])(
    "points a 404 that names no model (%s) at LLM_BASE_URL",
    (message) => {
      const failure = llmFailure(404, message);
      expect(failure.code).toBe("llm_failed");
      expect(failure.error).toMatch(/LLM_BASE_URL.*\/v1/);
    }
  );

  it("reports the provider's own message for unclassified failures", () => {
    expect(llmFailure(400, "Invalid tools schema").error).toBe(
      "Invalid tools schema"
    );
  });
});

describe("providerErrorMessage", () => {
  it.each([
    [
      "OpenAI and Ollama",
      { error: { message: "model 'x' not found", type: "not_found_error" } },
      "model 'x' not found",
    ],
    ["Mistral auth", { detail: "Invalid API Key" }, "Invalid API Key"],
    ["Mistral", { message: "Invalid model" }, "Invalid model"],
    ["a plain error string", { error: "bad request" }, "bad request"],
    ["a validation array", { detail: [{ msg: "field required" }] }, undefined],
    ["a non-JSON body", null, undefined],
  ])("reads %s error bodies", (_, body, expected) => {
    expect(providerErrorMessage(body)).toBe(expected);
  });
});
