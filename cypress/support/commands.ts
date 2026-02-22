declare global {
  namespace Cypress {
    interface Chainable {
      login(email: string, password: string): Chainable<void>;
      loginAsAdmin(): Chainable<void>;
      loginAsAlice(): Chainable<void>;
      loginAsBob(): Chainable<void>;
      verifyFlag(flag: string): Chainable<void>;
    }
  }
}

Cypress.Commands.add("login", (email: string, password: string) => {
  cy.request({
    method: "POST",
    url: "/api/auth/login",
    body: { email, password },
  }).then((response) => {
    expect(response.status).to.eq(200);
    const user = response.body.user;
    window.localStorage.setItem("user", JSON.stringify(user));
  });
});

Cypress.Commands.add("loginAsAdmin", () => {
  cy.login("admin@oss.com", "admin");
});

Cypress.Commands.add("loginAsAlice", () => {
  cy.login("alice@example.com", "iloveduck");
});

Cypress.Commands.add("loginAsBob", () => {
  cy.login("bob@example.com", "qwerty");
});

Cypress.Commands.add("verifyFlag", (flag: string) => {
  cy.request({
    method: "POST",
    url: "/api/flags/verify",
    body: { flag },
  }).then((response) => {
    expect(response.status).to.eq(200);
    expect(response.body.valid).to.eq(true);
  });
});

export {};
