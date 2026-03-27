describe("Race Condition - Coupon Abuse (E2E)", () => {
  beforeEach(() => {
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
    });
  });

  it("user can enter a coupon code at checkout and see the updated total", () => {
    cy.visit("/checkout");

    cy.contains("Have a promo code?").click();

    cy.get("input[placeholder='Enter code']").type("FLASHSALE");
    cy.contains("button", "Apply").click();

    cy.contains(/50% off|already been used/i, { timeout: 5000 });
  });

  it("shows an error message for an invalid coupon code", () => {
    cy.visit("/checkout");

    cy.contains("Have a promo code?").click();

    cy.get("input[placeholder='Enter code']").type("INVALIDCODE");
    cy.contains("button", "Apply").click();

    cy.contains(/coupon not found/i, { timeout: 5000 });
  });
});
