describe("Profile (E2E)", () => {
  beforeEach(() => {
    cy.loginAsAlice();
  });

  it("displays user profile information", () => {
    cy.visit("/profile");

    cy.contains("alice@example.com").should("be.visible");
    cy.contains("CUSTOMER").should("be.visible");
    cy.get("input#displayName").should("be.visible");
    cy.get("textarea#bio").should("be.visible");
  });

  it("updates display name", () => {
    const displayName = `Alice E2E ${Date.now()}`;

    cy.visit("/profile");

    cy.get("input#displayName").clear().type(displayName);

    cy.intercept("POST", "/api/user/profile").as("updateProfile");
    cy.contains("button", "Save Profile").click();
    cy.wait("@updateProfile").then((interception) => {
      expect(interception.response?.statusCode).to.eq(200);
    });

    cy.reload();
    cy.get("input#displayName").should("have.value", displayName);
  });

  it("updates bio", () => {
    const bio = `E2E test bio ${Date.now()}`;

    cy.visit("/profile");

    cy.get("textarea#bio").clear().type(bio);

    cy.intercept("POST", "/api/user/profile").as("updateProfile");
    cy.contains("button", "Save Profile").click();
    cy.wait("@updateProfile").then((interception) => {
      expect(interception.response?.statusCode).to.eq(200);
    });

    cy.reload();
    cy.get("textarea#bio").should("have.value", bio);
  });

  it("redirects to login when not authenticated", () => {
    cy.clearCookies();
    cy.window().then((win) => win.localStorage.clear());

    cy.visit("/profile");

    cy.url({ timeout: 10000 }).should("include", "/login");
  });
});
