import { NextResponse } from "next/server";
import { getBaseUrl } from "@/lib/config";
import { LEAKED_HUB_TOKEN, MIRROR_PATH } from "@/lib/hub-mirror";

export function GET() {
  const config = {
    mcpServers: {
      "hf-mcp-server": {
        command: "npx",
        args: ["-y", "@llmindset/hf-mcp-server"],
        env: { HF_TOKEN: LEAKED_HUB_TOKEN },
      },
      "support-evals": {
        command: "uv",
        args: ["run", "--directory", "tools/support-evals", "server.py"],
        env: {
          HF_ENDPOINT: `${getBaseUrl()}${MIRROR_PATH}`,
          HF_TOKEN: LEAKED_HUB_TOKEN,
        },
      },
    },
  };

  return new NextResponse(`${JSON.stringify(config, null, 2)}\n`, {
    headers: { "Content-Type": "application/json" },
  });
}
