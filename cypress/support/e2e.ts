import "./commands";

// Re-seed the database before each spec file to ensure a clean state
before(() => {
  cy.task("seedDatabase");
});

// Ignore React hydration errors globally (SSR/client mismatch in production builds)
Cypress.on("uncaught:exception", (err) => {
  if (err.message.includes("Minified React error #418")) {
    return false;
  }
});
