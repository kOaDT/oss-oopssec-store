import { createServer, type IncomingMessage } from "http";
import { apiRequest } from "./api";

export const LLM_STUB_URL = "http://127.0.0.1:11435/v1";
export const LLM_STUB_MODEL = "stub";
export const LLM_STUB_API_KEY = "stub-key";

const SERVER_COMMAND = `LLM_BASE_URL=${LLM_STUB_URL} LLM_MODEL=${LLM_STUB_MODEL} LLM_API_KEY=${LLM_STUB_API_KEY} npm run dev`;

interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

interface ChatMessage {
  role: string;
  content?: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  tools?: { type: "function"; function: { name: string } }[];
}

export interface RecordedRequest {
  authorization?: string;
  body: ChatRequest;
}

export interface LlmStub {
  requests: RecordedRequest[];
  close(): Promise<void>;
}

/**
 * A gullible model: it calls any offered tool the latest message names, once,
 * and otherwise answers by repeating everything it was told except the user's
 * words — system prompt and tool results included.
 */
function nextMessage({ messages, tools = [] }: ChatRequest): ChatMessage {
  const latest = messages[messages.length - 1]?.content ?? "";
  const called = messages.flatMap((m) => m.tool_calls ?? []);
  const requested = tools
    .map((tool) => tool.function.name)
    .find(
      (name) =>
        latest.includes(name) && !called.some((c) => c.function.name === name)
    );

  if (requested) {
    return {
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: `call_${called.length}`,
          type: "function",
          function: { name: requested, arguments: "{}" },
        },
      ],
    };
  }

  return {
    role: "assistant",
    content: messages
      .filter((m) => m.role !== "user" && m.content)
      .map((m) => m.content)
      .join("\n\n"),
  };
}

async function readJson(req: IncomingMessage): Promise<ChatRequest> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf-8"));
}

export async function startLlmStub(): Promise<LlmStub> {
  const { hostname, port, pathname } = new URL(LLM_STUB_URL);
  const completionsPath = `${pathname}/chat/completions`;
  const requests: RecordedRequest[] = [];

  const server = createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== completionsPath) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message: "not found" } }));
      return;
    }

    const body = await readJson(req);
    requests.push({ authorization: req.headers.authorization, body });
    const message = nextMessage(body);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        id: `chatcmpl-${requests.length}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: body.model,
        choices: [
          {
            index: 0,
            message,
            finish_reason: message.tool_calls ? "tool_calls" : "stop",
          },
        ],
      })
    );
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(port), hostname, resolve);
  });

  return {
    requests,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      ),
  };
}

/** Fails the suite unless the running server sends its completions to the stub. */
export async function expectServerUsesStub(stub: LlmStub): Promise<void> {
  await apiRequest("/api/ai-assistant", {
    method: "POST",
    body: JSON.stringify({ message: "Hello" }),
  });
  if (stub.requests.length === 0) {
    throw new Error(
      `The server under test did not call the LLM stub at ${LLM_STUB_URL}. Restart it with:\n  ${SERVER_COMMAND}`
    );
  }
  stub.requests.length = 0;
}
