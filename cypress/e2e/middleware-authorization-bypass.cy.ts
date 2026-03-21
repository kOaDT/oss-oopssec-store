describe("Middleware Authorization Bypass", () => {
  it("redirects unauthenticated users from /monitoring/internal-status to /login", () => {
    cy.visit("/monitoring/internal-status", { failOnStatusCode: false });
    cy.url().should("include", "/login");
  });
});
