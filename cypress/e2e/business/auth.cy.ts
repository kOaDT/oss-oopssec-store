describe("Authentication (E2E)", () => {
  describe("Login", () => {
    it("logs in with valid credentials and redirects to home", () => {
      cy.visit("/login");

      cy.get("input#email").type("alice@example.com");
      cy.get("input#password").type("iloveduck");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("not.include", "/login");
      cy.url().should("eq", Cypress.config().baseUrl + "/");
    });

    it("shows error for invalid credentials", () => {
      cy.visit("/login");

      cy.get("input#email").type("alice@example.com");
      cy.get("input#password").type("wrongpassword");
      cy.get("form").submit();

      cy.get(".border-red-200").should("be.visible");
      cy.url().should("include", "/login");
    });

    it("admin login redirects to /admin", () => {
      cy.visit("/login");

      cy.get("input#email").type("admin@oss.com");
      cy.get("input#password").type("admin");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("include", "/admin");
    });
  });

  describe("Signup", () => {
    it("creates a new account and redirects to home", () => {
      const email = `e2e-${Date.now()}@example.com`;

      cy.visit("/signup");

      cy.get("input#email").type(email);
      cy.get("input#password").type("securepass123");
      cy.get("input#passwordConfirmation").type("securepass123");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("not.include", "/signup");
    });

    it("shows error when passwords do not match", () => {
      cy.visit("/signup");

      cy.get("input#email").type("mismatch@example.com");
      cy.get("input#password").type("password1");
      cy.get("input#passwordConfirmation").type("password2");
      cy.get("form").submit();

      cy.get(".border-red-200").should("contain.text", "do not match");
      cy.url().should("include", "/signup");
    });

    it("shows error for password too short", () => {
      cy.visit("/signup");

      cy.get("input#email").type("short@example.com");
      cy.get("input#password").type("12345");
      cy.get("input#passwordConfirmation").type("12345");
      cy.get("form").submit();

      cy.get(".border-red-200").should("contain.text", "at least 6 characters");
    });
  });

  describe("Logout", () => {
    it("logs out and redirects to home", () => {
      cy.visit("/login");
      cy.get("input#email").type("alice@example.com");
      cy.get("input#password").type("iloveduck");
      cy.get("form").submit();

      cy.url({ timeout: 10000 }).should("not.include", "/login");
      cy.contains("alice@example.com", { timeout: 10000 }).should("be.visible");

      cy.contains("button", "Logout").click();

      cy.url({ timeout: 10000 }).should("eq", Cypress.config().baseUrl + "/");
      cy.contains("button", "Logout").should("not.exist");
    });
  });
});
