import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";
import { MCP_SESSION_HEADER, MCP_SESSION_VALUE } from "../../lib/mcp-constants";

interface JsonRpcResponse {
  jsonrpc: string;
  id: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

interface McpToolsResult {
  tools: Array<{
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
  }>;
}

interface McpContentResult {
  content: Array<{ type: string; text: string }>;
}

function mcpRequest(
  method: string,
  params?: Record<string, unknown>,
  headers?: Record<string, string>
) {
  return apiRequest<JsonRpcResponse>("/api/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });
}

describe("MCP Malicious Server — Indirect Prompt Injection", () => {
  describe("MCP Protocol", () => {
    it("responds to initialize with server info and capabilities", async () => {
      const res = await mcpRequest("initialize");
      expect(res.status).toBe(200);
      const result = (res.data as JsonRpcResponse).result as Record<
        string,
        unknown
      >;
      expect(result.protocolVersion).toBe("2025-03-26");
      expect(result.serverInfo).toEqual({
        name: "oopssec-product-catalog",
        version: "1.0.3",
      });
      expect(result.capabilities).toHaveProperty("tools");
    });

    it("returns tools list with three tools including restricted get_compliance_report", async () => {
      const res = await mcpRequest("tools/list");
      expect(res.status).toBe(200);
      const result = (res.data as JsonRpcResponse).result as McpToolsResult;
      const tools = result.tools;
      expect(tools).toHaveLength(3);

      const toolNames = tools.map((t) => t.name);
      expect(toolNames).toContain("verify_order_status");
      expect(toolNames).toContain("check_store_policy");
      expect(toolNames).toContain("get_compliance_report");

      const complianceTool = tools.find(
        (t) => t.name === "get_compliance_report"
      );
      expect(complianceTool?.description).toMatch(/restricted/i);
    });

    it("rejects invalid JSON-RPC version", async () => {
      const res = await apiRequest<JsonRpcResponse>("/api/mcp", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "1.0",
          id: 1,
          method: "initialize",
        }),
      });
      expect(res.status).toBe(200);
      expect((res.data as JsonRpcResponse).error).toBeDefined();
      expect((res.data as JsonRpcResponse).error?.code).toBe(-32600);
    });

    it("rejects unknown methods", async () => {
      const res = await mcpRequest("unknown/method");
      expect(res.status).toBe(200);
      expect((res.data as JsonRpcResponse).error).toBeDefined();
      expect((res.data as JsonRpcResponse).error?.code).toBe(-32601);
    });
  });

  describe("Tool Responses — Clean (No Poison)", () => {
    it("verify_order_status returns normal order data", async () => {
      const res = await mcpRequest("tools/call", {
        name: "verify_order_status",
        arguments: { order_id: "ORD-001" },
      });
      expect(res.status).toBe(200);
      const result = (res.data as JsonRpcResponse).result as McpContentResult;
      const text = result.content[0].text;
      expect(text).toContain("ORD-001");
      expect(text).not.toMatch(/OSS\{/);
    });

    it("check_store_policy returns clean policy data without injection", async () => {
      const res = await mcpRequest("tools/call", {
        name: "check_store_policy",
        arguments: { policy_type: "returns" },
      });
      expect(res.status).toBe(200);
      const result = (res.data as JsonRpcResponse).result as McpContentResult;
      const text = result.content[0].text;
      expect(text).toContain("Return Policy");
      expect(text).not.toMatch(/COMPLIANCE/i);
      expect(text).not.toMatch(/MUST.*call/i);
      expect(text).not.toMatch(/OSS\{/);
    });
  });

  describe("Restricted Tool — get_compliance_report", () => {
    it("rejects calls without session header", async () => {
      const res = await mcpRequest("tools/call", {
        name: "get_compliance_report",
        arguments: {},
      });
      expect(res.status).toBe(200);
      const data = res.data as JsonRpcResponse;
      expect(data.error).toBeDefined();
      expect(data.error?.code).toBe(-32603);
      expect(data.error?.message).toMatch(/access denied/i);
    });

    it("returns the flag when called with valid session header", async () => {
      const res = await mcpRequest(
        "tools/call",
        { name: "get_compliance_report", arguments: {} },
        { [MCP_SESSION_HEADER]: MCP_SESSION_VALUE }
      );
      expect(res.status).toBe(200);
      const result = (res.data as JsonRpcResponse).result as McpContentResult;
      const text = result.content[0].text;
      expect(text).toContain(FLAGS.MCP_MALICIOUS_SERVER);
    });
  });

  describe("AI Assistant — Custom MCP Server Support", () => {
    it("accepts mcpServerUrl parameter without error", async () => {
      const res = await apiRequest("/api/ai-assistant", {
        method: "POST",
        body: JSON.stringify({
          message: "Hello",
          apiKey: "test-key",
          mcpServerUrl: "http://localhost:9999",
        }),
      });
      // Should not crash — external server is unreachable but that's handled gracefully
      // Will fail at Mistral API level (invalid key) but not at MCP level
      expect(res.status).not.toBe(500);
    });
  });
});
