// The checker is mounted once in the root layout. These specs change what
// /api/flags/progress returns while the tab stays open (another client solving
// a flag, a database reset) and expect the checker to follow the server.

const TOTAL_FLAGS = 38;

const progressBody = (found: number) => ({
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
  totalFlags: TOTAL_FLAGS,
  statsByCategory: {},
  statsByDifficulty: {},
});

describe("Flag checker progress (E2E)", () => {
  let progress = progressBody(0);

  const visitWithProgress = (found: number) => {
    progress = progressBody(found);
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

  const serverProgressBecomes = (found: number) =>
    cy.then(() => {
      progress = progressBody(found);
    });

  const openChecker = () => cy.get('button[aria-label="Check flag"]').click();
  const closeChecker = () => cy.get('button[aria-label="Close"]').click();

  const submitFlag = (flag: string) => {
    cy.get("input#flag-input").type(flag, { parseSpecialCharSequences: false });
    cy.contains("button", "Verify").click();
  };

  const counter = (found: number) => `${found}/${TOTAL_FLAGS} flags found`;

  it("picks up a flag solved from another client when reopened", () => {
    visitWithProgress(9);
    openChecker();
    cy.contains(counter(9)).should("be.visible");
    closeChecker();

    serverProgressBecomes(10);
    openChecker();
    cy.contains(counter(10)).should("be.visible");
  });

  it("refreshes the counter after an invalid submission", () => {
    visitWithProgress(9);
    openChecker();
    cy.contains(counter(9)).should("be.visible");

    serverProgressBecomes(10);
    submitFlag("OSS{not_a_real_flag}");
    cy.contains("Invalid flag. Try again!").should("be.visible");
    cy.contains(counter(10)).should("be.visible");
  });

  it("ignores an older progress response that arrives last", () => {
    visitWithProgress(9);
    cy.intercept(
      { method: "GET", url: "/api/flags/progress", times: 1 },
      (req) => req.reply({ body: progressBody(9), delay: 1500 })
    ).as("slowProgress");
    openChecker();

    serverProgressBecomes(10);
    submitFlag("OSS{not_a_real_flag}");
    cy.contains(counter(10)).should("be.visible");

    cy.wait("@slowProgress");
    // Nothing on screen marks the late response being handled, so give it a
    // moment to land before checking it was discarded.
    cy.wait(300);
    cy.contains(counter(10)).should("be.visible");
  });

  it("confirms a new flag without a count when progress cannot be read", () => {
    visitWithProgress(9);
    openChecker();
    cy.contains(counter(9)).should("be.visible");

    cy.intercept("POST", "/api/flags/verify", {
      valid: true,
      alreadyFound: false,
      slug: "stub-flag-new",
    });
    cy.intercept("GET", "/api/flags/progress", {
      statusCode: 500,
      body: { error: "Failed to fetch progress" },
    });
    submitFlag("OSS{stubbed_valid_flag}");
    cy.contains("Congrats! Flag found!").should("be.visible");
    cy.contains(counter(9)).should("be.visible");
  });

  it("allows submitting again after the database is reset", () => {
    visitWithProgress(TOTAL_FLAGS);
    openChecker();
    cy.contains("h2", "All Flags Found").should("be.visible");
    cy.get("input#flag-input").should("not.exist");
    closeChecker();

    serverProgressBecomes(0);
    openChecker();
    cy.contains("h2", "Verify Flag").should("be.visible");
    cy.contains(counter(0)).should("be.visible");
    cy.get("input#flag-input").should("be.visible");
  });
});
