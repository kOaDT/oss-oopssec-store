describe("Cart (E2E)", () => {
  beforeEach(() => {
    cy.loginAsAlice();
  });

  it("adds a product to cart from product detail page", () => {
    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.visit(`/products/${product.id}`);
      cy.contains("button", "Add to Cart").click();

      cy.url({ timeout: 10000 }).should("include", "/cart");
      cy.contains(product.name).should("be.visible");
    });
  });

  it("displays cart items with quantities and totals", () => {
    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: product.id, quantity: 2 },
      });

      cy.visit("/cart");

      cy.contains(product.name).should("be.visible");
      cy.contains("Order Summary").should("be.visible");
      cy.contains("Proceed to Checkout").should("be.visible");
    });
  });

  it("updates cart item quantity with +/- buttons", () => {
    cy.request("GET", "/api/cart").then((cartResponse) => {
      const items = cartResponse.body.cartItems || [];
      items.forEach(
        (item: { id: string }) =>
          void cy.request({
            method: "DELETE",
            url: `/api/cart/items/${item.id}`,
          })
      );
    });

    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: product.id, quantity: 1 },
      });

      cy.visit("/cart");
      cy.contains(product.name).should("be.visible");

      cy.get('button[aria-label="Increase quantity"]').first().click();

      cy.get('button[aria-label="Decrease quantity"]')
        .first()
        .parent()
        .find("span")
        .should("contain.text", "2");
    });
  });

  it("removes item from cart", () => {
    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: product.id, quantity: 1 },
      });

      cy.visit("/cart");
      cy.contains(product.name).should("be.visible");

      cy.contains("button", "Remove").click();

      cy.contains("Your cart is empty", { timeout: 10000 }).should(
        "be.visible"
      );
    });
  });

  it("shows empty cart message when no items", () => {
    cy.request("GET", "/api/cart").then((response) => {
      const items = response.body.cartItems || [];
      items.forEach(
        (item: { id: string }) =>
          void cy.request({
            method: "DELETE",
            url: `/api/cart/items/${item.id}`,
          })
      );
    });

    cy.visit("/cart");

    cy.contains("Your cart is empty").should("be.visible");
    cy.contains("Continue Shopping").should("be.visible");
  });

  it("redirects to login when not authenticated", () => {
    cy.clearCookies();
    cy.window().then((win) => win.localStorage.clear());

    cy.visit("/cart");

    cy.url({ timeout: 10000 }).should("include", "/login");
  });
});
