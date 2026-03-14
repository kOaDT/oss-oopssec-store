describe("Reviews (E2E)", () => {
  it("submits a review on a product page", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      const productId = response.body[0].id;

      cy.visit(`/products/${productId}`);

      cy.contains("Reviews").should("be.visible");

      const reviewText = `Great product! Review ${Date.now()}`;
      cy.get("textarea#review").type(reviewText);

      cy.intercept("POST", `/api/products/${productId}/reviews`).as(
        "submitReview"
      );
      cy.contains("button", "Submit Review").click();

      cy.wait("@submitReview").then((interception) => {
        expect(interception.response?.statusCode).to.eq(201);
      });

      cy.contains(reviewText, { timeout: 10000 }).should("exist");
    });
  });

  it("pre-fills author with user email when logged in", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      const productId = response.body[0].id;
      cy.visit(`/products/${productId}`);

      cy.get("input#reviewAuthor").should("have.value", "alice@example.com");
    });
  });

  it("disables submit button when review content is empty", () => {
    cy.request("GET", "/api/products").then((response) => {
      const productId = response.body[0].id;
      cy.visit(`/products/${productId}`);

      cy.contains("button", "Submit Review").should("be.disabled");
    });
  });

  it("clears review form after successful submission", () => {
    cy.loginAsAlice();

    cy.request("GET", "/api/products").then((response) => {
      const productId = response.body[0].id;

      cy.visit(`/products/${productId}`);
      cy.get("textarea#review").type("Clearing test review");

      cy.intercept("POST", `/api/products/${productId}/reviews`).as(
        "submitReview"
      );
      cy.contains("button", "Submit Review").click();
      cy.wait("@submitReview");

      cy.get("textarea#review").should("have.value", "");
    });
  });
});
