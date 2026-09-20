describe("CSRF Admin Order Update", () => {
  beforeEach(() => {
    cy.loginAsAdmin();
  });

  it("awards the flag when the exploit page itself fires the request", () => {
    cy.intercept("POST", "/api/orders/ORD-003").as("csrf");

    cy.visit("/exploits/csrf-attack.html", {
      onBeforeLoad(win) {
        cy.stub(win, "alert").as("alert");
      },
    });

    cy.contains("Secure My Account Now").click();

    cy.wait("@csrf").then(({ response }) => {
      expect(response?.statusCode).to.eq(200);
      expect(response?.body.order.status).to.eq("DELIVERED");
      expect(response?.body.flag).to.match(/^OSS\{/);
    });
  });
});
