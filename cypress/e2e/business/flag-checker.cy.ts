// The checker is mounted once in the root layout. These specs change what
// /api/flags/progress returns while the tab stays open (another client solving
// a flag, a database reset) and expect the checker to follow the server.

const progressBody = (found: number, total: number) => ({
  foundFlags: Array.from({ length: found }, (_, i) => ({
    slug: `stub-flag-${i}`,
    category: "OTHER",
    difficulty: "EASY",
    cve: null,
    cwe: null,
    owasp: null,
    walkthroughSlug: null,
    foundAt: new Date(0).toISOString(),
  })),
  initializedAt: null,
  totalFlags: total,
  statsByCategory: {},
  statsByDifficulty: {},
});

describe("Flag checker progress (E2E)", () => {
  let progress = progressBody(0, 0);

  const visitWithProgress = (found: number, total: number) => {
    progress = progressBody(found, total);
    cy.intercept("GET", "/api/flags/progress", (req) => req.reply(progress)).as(
      "progress"
    );
    cy.visit("/", {
      onBeforeLoad(win) {
        win.localStorage.setItem("oss_onboarding_seen", "1");
      },
    });
    cy.wait("@progress");
  };

  const serverProgressBecomes = (found: number, total: number) =>
    cy.then(() => {
      progress = progressBody(found, total);
    });

  const openChecker = () => cy.get('button[aria-label="Check flag"]').click();
  const closeChecker = () => cy.get('button[aria-label="Close"]').click();

  it("picks up a flag solved from another client when reopened", () => {
    visitWithProgress(9, 37);
    openChecker();
    cy.contains("9/37 flags found").should("be.visible");
    closeChecker();

    serverProgressBecomes(10, 37);
    openChecker();
    cy.contains("10/37 flags found").should("be.visible");
  });

  it("refreshes the counter after an invalid submission", () => {
    visitWithProgress(9, 37);
    openChecker();
    cy.contains("9/37 flags found").should("be.visible");

    serverProgressBecomes(10, 37);
    cy.get("input#flag-input").type("OSS{not_a_real_flag}", {
      parseSpecialCharSequences: false,
    });
    cy.contains("button", "Verify").click();
    cy.contains("Invalid flag. Try again!").should("be.visible");
    cy.contains("10/37 flags found").should("be.visible");
  });

  it("refreshes the counter on client-side navigation", () => {
    visitWithProgress(9, 37);

    serverProgressBecomes(10, 37);
    cy.intercept("GET", "/api/flags/progress", (req) => req.reply(progress)).as(
      "navigationProgress"
    );
    cy.contains("header a:visible", "About").click();
    cy.location("pathname").should("eq", "/about");
    cy.wait("@navigationProgress");

    // Opening the checker must not be what brings the counter up to date.
    cy.intercept("GET", "/api/flags/progress", { forceNetworkError: true });
    openChecker();
    cy.contains("10/37 flags found").should("be.visible");
  });

  it("allows submitting again after the database is reset", () => {
    visitWithProgress(38, 38);
    openChecker();
    cy.contains("h2", "All Flags Found").should("be.visible");
    cy.get("input#flag-input").should("not.exist");
    closeChecker();

    serverProgressBecomes(0, 38);
    openChecker();
    cy.contains("h2", "Verify Flag").should("be.visible");
    cy.contains("0/38 flags found").should("be.visible");
    cy.get("input#flag-input").should("be.visible");
  });
});
