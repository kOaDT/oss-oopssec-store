describe("MCP Malicious Server — Indirect Prompt Injection (E2E)", () => {
  it("MCP server tools/list returns three tools including restricted one", () => {
    cy.request({
      method: "POST",
      url: "/api/mcp",
      body: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      },
    }).then((response) => {
      expect(response.status).to.eq(200);
      const tools = response.body.result.tools;
      expect(tools).to.have.length(3);

      const names = tools.map((t: { name: string }) => t.name);
      expect(names).to.include("verify_order_status");
      expect(names).to.include("check_store_policy");
      expect(names).to.include("get_compliance_report");
    });
  });

  it("check_store_policy returns clean policy data (no poison)", () => {
    cy.request({
      method: "POST",
      url: "/api/mcp",
      body: {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "check_store_policy",
          arguments: { policy_type: "returns" },
        },
      },
    }).then((response) => {
      expect(response.status).to.eq(200);
      const text = response.body.result.content[0].text;
      expect(text).to.contain("Return Policy");
      expect(text).not.to.match(/COMPLIANCE/i);
      expect(text).not.to.match(/OSS\{.*\}/);
    });
  });

  it("get_compliance_report is denied without session header", () => {
    cy.request({
      method: "POST",
      url: "/api/mcp",
      body: {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "get_compliance_report",
          arguments: {},
        },
      },
    }).then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body.error).to.exist;
      expect(response.body.error.message).to.match(/access denied/i);
    });
  });

  it("get_compliance_report returns flag with valid session header", () => {
    cy.request({
      method: "POST",
      url: "/api/mcp",
      // Must match MCP_SESSION_HEADER / MCP_SESSION_VALUE from app/api/mcp/route.ts
      headers: {
        "X-MCP-Session": "oopssec-internal-agent",
      },
      body: {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "get_compliance_report",
          arguments: {},
        },
      },
    }).then((response) => {
      expect(response.status).to.eq(200);
      const text = response.body.result.content[0].text;
      expect(text).to.match(/OSS\{[^}]+\}/);

      const flagMatch = text.match(/OSS\{[^}]+\}/);
      expect(flagMatch).not.to.be.null;
      cy.verifyFlag(flagMatch![0]);
    });
  });

  it("AI assistant chat UI has MCP server settings", () => {
    cy.visit("/support/ai-assistant");
    cy.window().then((win) => {
      win.localStorage.setItem("mistral_api_key", "test-key");
    });
    cy.reload();

    cy.get("button[title='MCP Server Settings']").should("be.visible").click();
    cy.get("input#mcpServerUrl").should("be.visible");
    cy.contains("Connect an external MCP server").should("be.visible");
  });
});
