const XSS_PAYLOAD = '<img src=x onerror="document.title=1">';

describe("Self-XSS Profile Injection", () => {
  beforeEach(() => {
    cy.loginAsAlice();
  });

  afterEach(() => {
    // Clean up bio
    cy.request({
      method: "POST",
      url: "/api/user/profile",
      body: { bio: "" },
      headers: { Referer: "http://localhost:3000/profile" },
    });
  });

  it("renders XSS payload in profile bio via dangerouslySetInnerHTML", () => {
    cy.visit("/profile");

    cy.get("textarea#bio")
      .clear()
      .type(XSS_PAYLOAD, { parseSpecialCharSequences: false });
    cy.get("button[type=submit]").contains("Save Profile").click();

    cy.get('img[onerror*="document.title"]', { timeout: 5000 })
      .should("exist")
      .and("have.attr", "onerror")
      .and("include", "document.title=1");
  });
});
