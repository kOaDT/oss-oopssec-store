import "@testing-library/jest-dom";
import { execSync } from "child_process";

const BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";

async function waitForServer(maxRetries = 10, delayMs = 300): Promise<void> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(BASE_URL, { method: "HEAD" });
      if (res.ok || res.status === 308) return;
    } catch {
      // server not ready yet
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
}

beforeAll(async () => {
  execSync("npx tsx prisma/seed.ts", { stdio: "ignore" });
  await waitForServer();
});
