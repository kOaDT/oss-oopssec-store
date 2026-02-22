import "./commands";

// Ignore React hydration errors globally (SSR/client mismatch in production builds)
Cypress.on("uncaught:exception", (err) => {
  if (err.message.includes("Minified React error #418")) {
    return false;
  }
});
