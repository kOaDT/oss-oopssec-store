const XSS_PAYLOAD = '<img src=x onerror="document.title=1">';

describe("Cross-Site Scripting (XSS)", () => {
  it("renders XSS payload in product page as unsanitized HTML", () => {
    cy.request("GET", "/api/products").then((response) => {
      expect(response.status).to.eq(200);
      const products = response.body;
      expect(products).to.be.an("array").and.not.to.be.empty;
      const productId = products[0].id;
      cy.visit(`/products/${productId}`);
    });

    cy.get("#review").type(XSS_PAYLOAD);
    cy.get("button[type=submit]").contains("Submit Review").click();

    cy.get("#review", { timeout: 5000 }).should("have.value", "");
    cy.get('img[onerror*="document.title"]', { timeout: 5000 })
      .should("exist")
      .and("have.attr", "onerror")
      .and("include", "document.title=1");
  });
});
