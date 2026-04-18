const BASE64_SECRET = "T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=";
const FLAG = "OSS{public_3nvir0nment_v4ri4bl3}";

describe("Public Environment Variable (E2E)", () => {
  it("NEXT_PUBLIC_PAYMENT_SECRET is exposed in .env.local with client-visible prefix", () => {
    // Any env var prefixed with NEXT_PUBLIC_ is automatically bundled
    // into client-side JavaScript by Next.js, exposing it to the browser.
    cy.readFile(".env.local").then((content: string) => {
      expect(content).to.include("NEXT_PUBLIC_PAYMENT_SECRET");
      expect(content).to.include(BASE64_SECRET);
    });
  });

  it("base64 secret decodes to the flag", () => {
    const decoded = atob(BASE64_SECRET);
    expect(decoded).to.eq(FLAG);
  });

  it("decoded secret is valid flag via flags API", () => {
    cy.verifyFlag(FLAG);
  });

  it("checkout page leaks the secret in the X-Payment-Auth header on order creation", () => {
    cy.request("GET", "/api/products").then((response) => {
      expect(response.status).to.eq(200);
      const productId = response.body[0].id;

      cy.visit("/login");
      cy.get("input#email").type("alice@example.com");
      cy.get("input#password").type("iloveduck");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("not.include", "/login");
      cy.visit(`/products/${productId}`);
      cy.contains("button", "Add to Cart").click();

      cy.intercept("POST", "/api/orders").as("createOrder");
      cy.visit("/checkout");
      cy.contains("button", "Complete Payment").click();

      cy.wait("@createOrder").then((interception) => {
        expect(interception.request.headers).to.have.property(
          "x-payment-auth",
          BASE64_SECRET
        );
      });
    });
  });
});
