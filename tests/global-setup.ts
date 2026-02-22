export default async function globalSetup() {
  const baseUrl = process.env.TEST_BASE_URL || "http://localhost:3000";

  try {
    const response = await fetch(baseUrl, { method: "HEAD" });
    if (!response.ok && response.status !== 308) {
      throw new Error(`Server responded with status ${response.status}`);
    }
  } catch (error) {
    throw new Error(
      `Test server is not running at ${baseUrl}. Start it with "npm run dev" before running tests.\n${error}`
    );
  }
}
