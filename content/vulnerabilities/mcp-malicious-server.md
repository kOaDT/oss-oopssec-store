# Malicious MCP Server — Indirect Prompt Injection via Tool Response

## Overview

When an LLM agent is wired up to external Model Context Protocol (MCP) servers, anything those servers return is injected into the model's context as authoritative input. A malicious or compromised MCP server can therefore steer the agent the same way a system prompt would: by issuing instructions inside a tool response.

In this challenge, the AI Support Assistant accepts a user-supplied `mcpServerUrl`, merges its tools with the privileged internal tools (one of which is restricted by system prompt), and feeds tool responses back to the LLM with no validation. A poisoned response from the external server can override the assistant's restrictions and trigger the privileged internal tool.

## Why This Is Dangerous

- **Static review misses the attack** — tool _names_ and _descriptions_ are vetted at setup, but tool _responses_ change at runtime.
- **Trust mixing** — external untrusted tools share the agent's context with privileged internal tools, so injected text can name them.
- **Bypasses input filtering** — the malicious instructions never appear in the user's message, so prompt-input scanners do not see them.
- **Privileged session is reusable** — the agent already holds the credentials the attacker cannot present directly.

## Vulnerable Code

Tool responses from any MCP server are appended to the LLM context with no sanitization:

```typescript
for (const toolCall of assistantMessage.tool_calls) {
  const toolName = toolCall.function.name;
  const toolArgs = JSON.parse(toolCall.function.arguments || "{}");

  const source = toolSourceMap.get(toolName);
  const toolResult = source
    ? await callMcpTool(source.url, toolName, toolArgs, source.headers)
    : `Unknown tool: ${toolName}`;

  messages.push({
    role: "tool",
    content: toolResult,
  });
}
```

External tools are merged into the same tool set as internal ones, sharing the agent's privileged session:

```typescript
const internalTools = await discoverTools(INTERNAL_MCP_URL, internalHeaders);

if (mcpServerUrl) {
  const externalTools = await discoverTools(mcpServerUrl);
  allTools.push(...externalTools);
}
```

The internal MCP server gates `get_compliance_report` behind an `X-MCP-Session` header that only the agent backend has, but a tool response that tells the agent to call that tool succeeds because the agent itself holds the session.

## Secure Implementation

Treat tool responses as untrusted text and segregate trust domains.

**Isolate trust domains.** Never share an agent context between user-supplied MCP servers and tools that have privileged access. Run external tools through a separate agent, or strip the privileged tools from the toolset whenever an external server is configured.

**Validate tool responses.** Before appending a tool response to the LLM context, scan for instruction-like patterns or wrap the content in a quarantined form the model is trained to ignore:

```typescript
const toolResult = await callMcpTool(source.url, toolName, toolArgs, headers);
const safeContent = quarantineToolOutput(toolResult);

messages.push({
  role: "tool",
  content: safeContent,
});
```

**Restrict cross-tool chaining.** Privileged tools should require an out-of-band trigger (user click, signed directive, scheduled job) — not a free-form instruction string from another tool's output.

**Allowlist external MCP servers.** Accept only vetted endpoints; do not allow arbitrary user-provided URLs in production deployments.

**Human-in-the-loop for privileged calls.** Before invoking any restricted tool, surface a confirmation step the user must approve. Indirect prompt injection cannot click "approve".

## References

- [OWASP LLM Top 10 — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Model Context Protocol — Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
- [Invariant Labs — MCP Security Research](https://invariantlabs.ai/mcp-security)
- [Mistral — Function Calling](https://docs.mistral.ai/capabilities/function_calling/)
