describe("Open Redirect on Login", () => {
  it("redirects to /internal/oauth/callback after login and displays the flag", () => {
    cy.visit("/login?redirect=/internal/oauth/callback");

    cy.get("#email").type("alice@example.com");
    cy.get("#password").type("iloveduck");
    cy.get("button[type=submit]").click();

    cy.url().should("include", "/internal/oauth/callback");
    cy.contains("OSS{0p3n_r3d1r3ct_l0g1n_byp4ss}").should("be.visible");
  });
});
