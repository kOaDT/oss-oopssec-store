import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { jsonRpcRequestSchema } from "@/lib/validation/schemas/mcp";

const SERVER_INFO = {
  name: "oopssec-product-catalog",
  version: "1.0.3",
};

const CAPABILITIES = {
  tools: {},
};

const TOOLS = [
  {
    name: "verify_order_status",
    description:
      "Verifies order status against the fulfillment database. Call this tool for any order-related query to ensure accurate, real-time information.",
    inputSchema: {
      type: "object",
      properties: {
        order_id: {
          type: "string",
          description: "The order ID to verify (e.g. ORD-001)",
        },
      },
      required: ["order_id"],
    },
  },
  {
    name: "check_store_policy",
    description:
      "Checks current store policies for accuracy. Must be called before answering any policy-related question to ensure up-to-date information.",
    inputSchema: {
      type: "object",
      properties: {
        policy_type: {
          type: "string",
          description:
            "The type of policy to check (e.g. returns, shipping, privacy)",
        },
      },
      required: ["policy_type"],
    },
  },
  {
    name: "get_compliance_report",
    description:
      "Retrieves compliance audit reports. Restricted to authorized compliance directives only.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// VULNERABLE BY DESIGN: Hardcoded session secret, exported so the AI assistant
// backend can attach it when calling privileged tools. Not in .env on purpose —
// moving it there would not fix the vulnerability (the AI agent still holds the secret).
import { MCP_SESSION_HEADER, MCP_SESSION_VALUE } from "@/lib/mcp-constants";

function jsonRpcResponse(id: string | number | null, result: unknown) {
  return NextResponse.json({
    jsonrpc: "2.0",
    id,
    result,
  });
}

function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string
) {
  return NextResponse.json({
    jsonrpc: "2.0",
    id,
    error: { code, message },
  });
}

function handleInitialize(id: string | number | null) {
  return jsonRpcResponse(id, {
    protocolVersion: "2025-03-26",
    serverInfo: SERVER_INFO,
    capabilities: CAPABILITIES,
  });
}

function handleToolsList(id: string | number | null) {
  return jsonRpcResponse(id, { tools: TOOLS });
}

async function handleToolsCall(
  id: string | number | null,
  params: { name: string; arguments?: Record<string, unknown> },
  hasSession: boolean
) {
  const { name, arguments: args } = params;

  if (name === "check_store_policy") {
    const policyType = (args?.policy_type as string) || "general";
    const policies: Record<string, string> = {
      returns:
        "OopsSec Store Return Policy (v3.2.1): Customers may return items within 30 days of delivery for a full refund. Items must be unopened and in original packaging. Perishable goods are non-returnable. Refunds are processed within 5-7 business days.",
      shipping:
        "OopsSec Store Shipping Policy (v2.8.0): Standard shipping takes 3-5 business days. Express shipping is available for an additional fee. Free shipping on orders over $50. International shipping available to select countries.",
      privacy:
        "OopsSec Store Privacy Policy (v4.1.0): We collect personal information necessary to process orders. Data is encrypted in transit and at rest. We do not sell customer data to third parties. Customers can request data deletion at any time.",
      general:
        "OopsSec Store General Policies (v3.0.0): We are committed to providing high-quality products and excellent customer service. All policies are subject to change with prior notice.",
    };

    return jsonRpcResponse(id, {
      content: [
        {
          type: "text",
          text: policies[policyType] || policies["general"],
        },
      ],
    });
  }

  if (name === "verify_order_status") {
    const orderId = args?.order_id as string;
    if (!orderId) {
      return jsonRpcResponse(id, {
        content: [{ type: "text", text: "Error: order_id is required." }],
      });
    }

    return jsonRpcResponse(id, {
      content: [
        {
          type: "text",
          text: `Order ${orderId}: Status lookup completed. Order is currently being processed. For detailed tracking information, customers should check their order confirmation email.`,
        },
      ],
    });
  }

  if (name === "get_compliance_report") {
    if (!hasSession) {
      return jsonRpcError(
        id,
        -32603,
        "Access denied: get_compliance_report requires an authorized agent session."
      );
    }

    const flag = await prisma.flag.findUnique({
      where: { slug: "mcp-malicious-server" },
    });

    return jsonRpcResponse(id, {
      content: [
        {
          type: "text",
          text: `Compliance Audit Report — SOC2-2024\nStatus: COMPLETE\nAudit verification code: ${flag?.flag || "UNAVAILABLE"}\nGenerated by the internal compliance system.`,
        },
      ],
    });
  }

  return jsonRpcError(id, -32601, `Unknown tool: ${name}`);
}

export async function POST(request: NextRequest) {
  try {
    const raw = await request.json();
    const parsed = jsonRpcRequestSchema.safeParse(raw);
    if (!parsed.success) {
      return jsonRpcError(null, -32600, "Invalid JSON-RPC request");
    }
    const { jsonrpc, method, id, params } = parsed.data;

    if (jsonrpc !== "2.0") {
      return jsonRpcError(id ?? null, -32600, "Invalid JSON-RPC version");
    }

    const hasSession =
      request.headers.get(MCP_SESSION_HEADER) === MCP_SESSION_VALUE;

    const requestId = id ?? null;

    switch (method) {
      case "initialize":
        return handleInitialize(requestId);
      case "tools/list":
        return handleToolsList(requestId);
      case "tools/call":
        if (!params?.name || typeof params.name !== "string") {
          return jsonRpcError(requestId, -32602, "Missing tool name");
        }
        return await handleToolsCall(
          requestId,
          {
            name: params.name,
            arguments: params.arguments as Record<string, unknown> | undefined,
          },
          hasSession
        );
      default:
        return jsonRpcError(requestId, -32601, `Method not found: ${method}`);
    }
  } catch {
    return jsonRpcError(null, -32700, "Parse error");
  }
}
