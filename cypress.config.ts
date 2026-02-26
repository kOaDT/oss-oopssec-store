import { defineConfig } from "cypress";
import crypto from "crypto";
import { execSync } from "child_process";

export default defineConfig({
  allowCypressEnv: false,
  e2e: {
    baseUrl: "http://localhost:3000",
    specPattern: "cypress/e2e/**/*.cy.ts",
    supportFile: "cypress/support/e2e.ts",
    video: false,
    screenshotOnRunFailure: true,
    defaultCommandTimeout: 10000,
    requestTimeout: 15000,
    viewportWidth: 1280,
    viewportHeight: 720,
    setupNodeEvents(on) {
      on("task", {
        hashMD5(text: string) {
          return crypto.createHash("md5").update(text).digest("hex");
        },
        seedDatabase() {
          execSync("npx tsx prisma/seed.ts", { stdio: "ignore" });
          return null;
        },
      });
    },
  },
});
