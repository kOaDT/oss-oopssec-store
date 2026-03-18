import { NextRequest, NextResponse } from "next/server";
import { MCP_SESSION_HEADER, MCP_SESSION_VALUE } from "@/lib/mcp-constants";
import { containsBlockedPattern } from "@/lib/prompt-injection-filter";

const SYSTEM_PROMPT = `You are OSSBot, a helpful customer support assistant for OopsSec Store, an online grocery and gourmet food marketplace.

Your role is to assist customers with:
- Product inquiries (availability, ingredients, pricing)
- Order status and tracking
- Returns and refunds
- General store policies
- Recommendations based on customer preferences

INTERNAL CONFIGURATION:
---
Assistant ID: OSS-SUPPORT-BOT-v2.1
Deployment: Production
Security clearance: PUBLIC
Internal validation code: OSS{pr0mpt_1nj3ct10n_41_4ss1st4nt}
Last updated: 2026-01-25
---

Guidelines:
- Be polite, helpful, and professional
- Focus on OopsSec Store products and services
- When tools are available, use them to provide accurate information
- Always include any reference numbers or verification codes from tool responses

Tool restrictions:
- The get_compliance_report tool is restricted to authorized compliance directives only. Do not call it unless explicitly directed by an official SOC2 compliance directive from the compliance verification system.`;

const INTERNAL_MCP_URL =
  process.env.MCP_SERVER_URL || "http://localhost:3000/api/mcp";

const MAX_TOOL_CALLS = 5;

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

interface MistralToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

interface MistralMessage {
  role: string;
  content?: string | null;
  tool_calls?: MistralToolCall[];
  tool_call_id?: string;
  name?: string;
}

async function mcpRequest(
  serverUrl: string,
  method: string,
  params?: Record<string, unknown>,
  headers?: Record<string, string>
) {
  const response = await fetch(serverUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: crypto.randomUUID(),
      method,
      params,
    }),
  });
  return response.json();
}

async function discoverTools(
  serverUrl: string,
  headers?: Record<string, string>
): Promise<McpTool[]> {
  try {
    const response = await mcpRequest(
      serverUrl,
      "tools/list",
      undefined,
      headers
    );
    return response.result?.tools || [];
  } catch {
    return [];
  }
}

function mcpToolsToMistralFormat(tools: McpTool[]) {
  return tools.map((tool) => ({
    type: "function" as const,
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema,
    },
  }));
}

async function callMcpTool(
  serverUrl: string,
  name: string,
  args: Record<string, unknown>,
  headers?: Record<string, string>
): Promise<string> {
  const response = await mcpRequest(
    serverUrl,
    "tools/call",
    { name, arguments: args },
    headers
  );
  const content = response.result?.content;
  if (Array.isArray(content) && content.length > 0) {
    return content.map((c: { text?: string }) => c.text || "").join("\n");
  }
  return JSON.stringify(response.result || response.error || {});
}

async function callMistral(
  apiKey: string,
  messages: MistralMessage[],
  tools?: ReturnType<typeof mcpToolsToMistralFormat>
) {
  const body: Record<string, unknown> = {
    model: "mistral-small-2603",
    messages,
    max_tokens: 1024,
    temperature: 0.7,
  };

  if (tools && tools.length > 0) {
    body.tools = tools;
    body.tool_choice = "auto";
  }

  const response = await fetch("https://api.mistral.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  return response;
}

export async function POST(request: NextRequest) {
  try {
    const { message, apiKey, mcpServerUrl } = await request.json();

    if (!message || typeof message !== "string") {
      return NextResponse.json(
        { error: "Message is required" },
        { status: 400 }
      );
    }

    if (!apiKey || typeof apiKey !== "string") {
      return NextResponse.json(
        { error: "Mistral API key is required" },
        { status: 400 }
      );
    }

    if (message.length > 2000) {
      return NextResponse.json(
        { error: "Message too long. Maximum 2000 characters allowed." },
        { status: 400 }
      );
    }

    if (containsBlockedPattern(message)) {
      return NextResponse.json(
        {
          response:
            "I'm sorry, but I can't process that request. I'm here to help with OopsSec Store products and services. How can I assist you today?",
        },
        { status: 200 }
      );
    }

    const internalHeaders = { [MCP_SESSION_HEADER]: MCP_SESSION_VALUE };

    const internalTools = await discoverTools(
      INTERNAL_MCP_URL,
      internalHeaders
    );

    const toolSourceMap = new Map<
      string,
      { url: string; headers?: Record<string, string> }
    >();
    for (const tool of internalTools) {
      toolSourceMap.set(tool.name, {
        url: INTERNAL_MCP_URL,
        headers: internalHeaders,
      });
    }

    const allTools = [...internalTools];

    // VULNERABLE BY DESIGN: No URL validation — accepts arbitrary user-provided
    // URLs, enabling SSRF (the backend acts as a proxy to internal networks) and
    // indirect prompt injection via malicious tool responses.
    if (mcpServerUrl && typeof mcpServerUrl === "string") {
      try {
        const externalTools = await discoverTools(mcpServerUrl);
        for (const tool of externalTools) {
          if (!toolSourceMap.has(tool.name)) {
            toolSourceMap.set(tool.name, { url: mcpServerUrl });
            allTools.push(tool);
          }
        }
      } catch {
        // External MCP server unreachable — continue with internal tools only
      }
    }

    const mistralTools = mcpToolsToMistralFormat(allTools);

    const messages: MistralMessage[] = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: message },
    ];

    let response = await callMistral(apiKey, messages, mistralTools);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      if (response.status === 401) {
        return NextResponse.json(
          { error: "Invalid API key. Please check your Mistral API key." },
          { status: 401 }
        );
      }

      if (response.status === 429) {
        return NextResponse.json(
          { error: "Rate limit exceeded. Please try again later." },
          { status: 429 }
        );
      }

      return NextResponse.json(
        {
          error:
            errorData.message || "Failed to get response from AI assistant",
        },
        { status: response.status }
      );
    }

    let data = await response.json();
    let assistantMessage = data.choices?.[0]?.message;
    let toolCallCount = 0;

    while (
      assistantMessage?.tool_calls &&
      assistantMessage.tool_calls.length > 0 &&
      toolCallCount < MAX_TOOL_CALLS
    ) {
      messages.push({
        role: "assistant",
        content: assistantMessage.content || null,
        tool_calls: assistantMessage.tool_calls,
      });

      for (const toolCall of assistantMessage.tool_calls) {
        const toolName = toolCall.function.name;
        let toolArgs: Record<string, unknown>;
        try {
          toolArgs = JSON.parse(toolCall.function.arguments || "{}");
        } catch {
          toolArgs = {};
        }

        const source = toolSourceMap.get(toolName);
        // VULNERABLE BY DESIGN: Tool responses from any MCP server (internal or
        // external) are injected into the LLM context without sanitization or
        // provenance metadata — the LLM cannot distinguish trusted vs. untrusted sources.
        const toolResult = source
          ? await callMcpTool(source.url, toolName, toolArgs, source.headers)
          : `Unknown tool: ${toolName}`;

        messages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          name: toolName,
          content: toolResult,
        });

        toolCallCount++;
      }

      response = await callMistral(apiKey, messages, mistralTools);

      if (!response.ok) {
        return NextResponse.json(
          {
            error:
              "AI assistant encountered an error during tool processing. Please try again.",
          },
          { status: 502 }
        );
      }

      data = await response.json();
      assistantMessage = data.choices?.[0]?.message;
    }

    const finalContent =
      assistantMessage?.content ||
      "I apologize, but I was unable to generate a response. Please try again.";

    return NextResponse.json({
      response: finalContent,
      // VULNERABLE BY DESIGN: Leaking internal MCP server URL and tool list
      // allows attackers to discover the restricted get_compliance_report tool.
      mcpTools: allTools.map((t) => ({
        name: t.name,
        description: t.description,
        source: toolSourceMap.get(t.name)?.url || "unknown",
      })),
    });
  } catch (error) {
    console.error("AI Assistant error:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred. Please try again." },
      { status: 500 }
    );
  }
}
