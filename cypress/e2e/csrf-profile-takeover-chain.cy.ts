describe("CSRF Profile Takeover Chain", () => {
  beforeEach(() => {
    cy.loginAsAlice();
  });

  afterEach(() => {
    // Clean up bio and drain csrfExploited
    cy.request({
      method: "POST",
      url: "/api/user/profile",
      body: { bio: "" },
      headers: { Referer: "http://localhost:3000/profile" },
    });
    cy.request("GET", "/api/user/profile");
  });

  it("exploit page is accessible", () => {
    cy.request({
      url: "/exploits/csrf-profile-takeover.html",
      failOnStatusCode: false,
    }).then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.include("csrf-profile-takeover");
    });
  });

  it("CSRF exploit updates bio and flag appears on /profile", () => {
    // Simulate CSRF: POST to profile endpoint without /profile Referer
    cy.request({
      method: "POST",
      url: "/api/user/profile",
      body: { bio: '<img src=x onerror="alert(1)">' },
      headers: { Referer: "https://evil.com" },
    }).then((response) => {
      expect(response.status).to.eq(200);
    });

    // Visit profile — csrfFlag should be returned and FlagDisplay rendered
    cy.visit("/profile");

    cy.contains("OSS{", { timeout: 10000 }).should("exist");
  });
});
