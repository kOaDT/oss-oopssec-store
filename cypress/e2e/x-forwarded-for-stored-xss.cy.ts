describe("Stored XSS via X-Forwarded-For header", () => {
  beforeEach(() => {
    // Inject a tracking entry with an XSS payload in the IP field
    cy.request({
      method: "POST",
      url: "/api/tracking",
      headers: {
        "X-Forwarded-For": `<img src=x onerror="alert('XSS')">`,
      },
      body: { path: "/xss-test", sessionId: "xss-test" },
    });
  });

  it("should render unsanitized HTML in the IP column", () => {
    cy.loginAsAdmin();
    cy.visit("/admin/analytics");

    // The IP column should contain the raw <img> tag rendered as HTML
    cy.get("table tbody tr td code img").should("exist");
  });

  it("should have an executable onerror attribute on the injected element", () => {
    cy.loginAsAdmin();
    cy.visit("/admin/analytics");

    // The injected <img> should have an onerror attribute — proof of XSS vector
    cy.get("table tbody tr td code img")
      .should("have.attr", "onerror")
      .and("contain", "alert");
  });
});
