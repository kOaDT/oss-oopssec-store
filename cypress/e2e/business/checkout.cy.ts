describe("Checkout (E2E)", () => {
  it("completes the full purchase flow", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: product.id, quantity: 1 },
      });

      cy.visit("/checkout");

      cy.contains("Checkout").should("be.visible");
      cy.contains("Delivery Address").should("be.visible");
      cy.contains("Order Items").should("be.visible");
      cy.contains(product.name).should("be.visible");

      cy.intercept("POST", "/api/orders").as("createOrder");
      cy.contains("button", "Complete Payment").click();

      cy.wait("@createOrder").then((interception) => {
        expect(interception.response?.statusCode).to.eq(200);
        expect(interception.response?.body).to.have.property("id");
        expect(interception.response?.body.id).to.match(/^ORD-\d{3,}$/);
        expect(interception.response?.body).to.have.property(
          "status",
          "PENDING"
        );
      });
    });
  });

  it("shows order items and delivery address on checkout page", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      const product = response.body[0];

      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: product.id, quantity: 3 },
      });

      cy.visit("/checkout");

      cy.contains(product.name).should("be.visible");
      cy.contains("Quantity:").should("be.visible");
      cy.contains("Order Summary").should("be.visible");
    });
  });

  it("navigates back to cart from checkout", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      cy.request({
        method: "POST",
        url: "/api/cart/add",
        body: { productId: response.body[0].id, quantity: 1 },
      });

      cy.visit("/checkout");

      cy.contains("Back to Cart").click();

      cy.url({ timeout: 10000 }).should("include", "/cart");
    });
  });

  it("redirects to login when not authenticated", () => {
    cy.clearCookies();
    cy.window().then((win) => win.localStorage.clear());

    cy.visit("/checkout");

    cy.url({ timeout: 10000 }).should("include", "/login");
  });
});
