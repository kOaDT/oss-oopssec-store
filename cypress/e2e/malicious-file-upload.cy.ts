const MALICIOUS_FILE_UPLOAD_FLAG = "OSS{m4l1c10us_f1l3_upl04d_xss}";

describe("Malicious File Upload (E2E)", () => {
  it("XSS triggers on product page when viewing product with uploaded malicious SVG", () => {
    cy.loginAsAdmin();

    cy.request("GET", "/api/products").then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.be.an("array").and.not.to.be.empty;
      const productId = response.body[0].id;

      cy.visit("/admin/products");

      cy.get("input[type=file]")
        .first()
        .selectFile(
          {
            contents: Cypress.Buffer.from(
              '<svg xmlns="http://www.w3.org/2000/svg" onload="window.parent.document.title=1"><rect width="100" height="100" fill="red"/></svg>'
            ),
            fileName: "xss.svg",
          },
          { force: true }
        );

      cy.contains("Image uploaded successfully", { timeout: 10000 }).should(
        "be.visible"
      );

      cy.visit(`/products/${productId}`);

      cy.document().its("title").should("eq", "1");
    });
  });

  it("flag is returned when uploading malicious SVG and can be verified", () => {
    cy.loginAsAdmin();

    cy.request("GET", "/api/products").then((_) => {
      cy.visit("/admin/products");

      cy.get("input[type=file]")
        .first()
        .selectFile(
          {
            contents: Cypress.Buffer.from(
              '<svg xmlns="http://www.w3.org/2000/svg"><script>document.title="malicious"</script></svg>'
            ),
            fileName: "malicious.svg",
          },
          { force: true }
        );

      cy.contains("Image uploaded successfully", { timeout: 10000 }).should(
        "be.visible"
      );

      cy.verifyFlag(MALICIOUS_FILE_UPLOAD_FLAG);
    });
  });
});
