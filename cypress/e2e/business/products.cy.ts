describe("Products (E2E)", () => {
  it("displays products on the home page", () => {
    cy.visit("/");

    cy.contains("Featured Products").should("be.visible");
    cy.get("a[href^='/products/']").should("have.length.greaterThan", 0);
  });

  it("navigates to product detail page", () => {
    cy.visit("/");

    cy.get("a[href^='/products/']").first().click();

    cy.url({ timeout: 10000 }).should("match", /\/products\/.+/);
    cy.get("h1").should("not.be.empty");
    cy.contains("Add to Cart").should("be.visible");
    cy.contains("In Stock").should("be.visible");
  });

  it("displays product price and description", () => {
    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.visit(`/products/${product.id}`);

      cy.get("h1").should("contain.text", product.name);
      cy.contains(`$${product.price.toFixed(2)}`).should("be.visible");
    });
  });

  it("shows quantity controls on product detail", () => {
    cy.request("GET", "/api/products").then((response) => {
      const productId = response.body[0].id;
      cy.visit(`/products/${productId}`);

      cy.get("input#qty").should("have.value", "1");

      cy.get('button[aria-label="Increase quantity"]').click();
      cy.get("input#qty").should("have.value", "2");

      cy.get('button[aria-label="Decrease quantity"]').click();
      cy.get("input#qty").should("have.value", "1");
    });
  });
});
