import { apiRequest } from "../helpers/api";
import { TUTORIAL_FLAG } from "@/lib/config";

interface VerifyResponse {
  valid: boolean;
  tutorial?: boolean;
  slug?: string;
  alreadyFound?: boolean;
  foundAt?: string;
}

interface ProgressResponse {
  foundFlags: { slug: string }[];
}

describe("Onboarding practice flag", () => {
  it("POST /api/flags/verify accepts the tutorial flag with { valid: true, tutorial: true }", async () => {
    const { status, data } = await apiRequest<VerifyResponse>(
      "/api/flags/verify",
      {
        method: "POST",
        body: JSON.stringify({ flag: TUTORIAL_FLAG }),
      }
    );

    expect(status).toBe(200);
    expect(data).toHaveProperty("valid", true);
    expect(data).toHaveProperty("tutorial", true);
  });

  it("short-circuits before the database, so it carries no real-flag fields", async () => {
    const { data } = await apiRequest<VerifyResponse>("/api/flags/verify", {
      method: "POST",
      body: JSON.stringify({ flag: TUTORIAL_FLAG }),
    });

    // Real flags return slug/alreadyFound/foundAt; the tutorial short-circuit must not.
    expect(data).not.toHaveProperty("slug");
    expect(data).not.toHaveProperty("alreadyFound");
    expect(data).not.toHaveProperty("foundAt");
  });

  it("never reaches the Hall of Fame, even when submitted repeatedly", async () => {
    const before = await apiRequest<ProgressResponse>("/api/flags/progress");
    const countBefore = before.data.foundFlags.length;

    await apiRequest("/api/flags/verify", {
      method: "POST",
      body: JSON.stringify({ flag: TUTORIAL_FLAG }),
    });
    await apiRequest("/api/flags/verify", {
      method: "POST",
      body: JSON.stringify({ flag: ` ${TUTORIAL_FLAG} ` }),
    });

    const after = await apiRequest<ProgressResponse>("/api/flags/progress");
    expect(after.data.foundFlags.length).toBe(countBefore);
  });
});
