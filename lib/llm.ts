export const DEFAULT_LLM_BASE_URL = "http://localhost:11434/v1";
export const DEFAULT_LLM_MODEL = "gemma4:e4b";

export interface LlmConfig {
  baseUrl: string;
  model: string;
  apiKey?: string;
}

export type LlmErrorCode =
  | "llm_unreachable"
  | "llm_model_not_found"
  | "llm_unauthorized"
  | "llm_rate_limited"
  | "llm_failed";

export interface LlmFailure {
  code: LlmErrorCode;
  status: number;
  error: string;
}

// Compose forwards unset variables as empty strings.
function readVar(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name]?.trim() || undefined;
}

function parseBaseUrl(value: string): string {
  const invalid = new Error(
    `LLM_BASE_URL must be an http(s) URL such as ${DEFAULT_LLM_BASE_URL}, got "${value}".`
  );
  let protocol: string;
  try {
    protocol = new URL(value).protocol;
  } catch {
    throw invalid;
  }
  if (protocol !== "http:" && protocol !== "https:") throw invalid;
  return value.replace(/\/+$/, "");
}

export function resolveLlmConfig(
  env: NodeJS.ProcessEnv = process.env
): LlmConfig {
  return {
    baseUrl: parseBaseUrl(readVar(env, "LLM_BASE_URL") ?? DEFAULT_LLM_BASE_URL),
    model: readVar(env, "LLM_MODEL") ?? DEFAULT_LLM_MODEL,
    apiKey: readVar(env, "LLM_API_KEY"),
  };
}

export const LLM_UNREACHABLE: LlmFailure = {
  code: "llm_unreachable",
  status: 502,
  error: "The AI assistant could not reach its language model.",
};

/** Maps a non-2xx answer from the chat completions endpoint to the route's reply. */
export function llmFailure(
  status: number,
  providerMessage?: string
): LlmFailure {
  if (status === 401 || status === 403) {
    return {
      code: "llm_unauthorized",
      status: 502,
      error: "The language model endpoint rejected the server's credentials.",
    };
  }
  if (status === 404) {
    return {
      code: "llm_model_not_found",
      status: 502,
      error: "The configured language model is not available.",
    };
  }
  if (status === 429) {
    return {
      code: "llm_rate_limited",
      status: 429,
      error: "Rate limit exceeded. Please try again later.",
    };
  }
  return {
    code: "llm_failed",
    status: 502,
    error: providerMessage || "Failed to get response from AI assistant",
  };
}

/** Error text from an OpenAI-style, Ollama or Mistral error body. */
export function providerErrorMessage(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const { error, message, detail } = body as Record<string, unknown>;
  const nested =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>).message
      : error;
  const candidate = [nested, message, detail].find(
    (value) => typeof value === "string" && value.length > 0
  );
  return candidate as string | undefined;
}
