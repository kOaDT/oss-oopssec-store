import * as fs from "fs";
import * as path from "path";
import { FLAGS } from "../helpers/flags";

const BASE64_SECRET = "T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=";

function decodeBase64(value: string): string {
  return Buffer.from(value, "base64").toString("utf-8");
}

describe("Public Environment Variable (unit)", () => {
  it("base64 value decodes to flag", () => {
    const decoded = decodeBase64(BASE64_SECRET);
    expect(decoded).toBe(FLAGS.PUBLIC_ENVIRONMENT_VARIABLE);
  });

  it("NEXT_PUBLIC_PAYMENT_SECRET env var exists in .env.local", () => {
    const envPath = path.join(process.cwd(), ".env.local");
    expect(fs.existsSync(envPath)).toBe(true);

    const content = fs.readFileSync(envPath, "utf-8");
    expect(content).toContain("NEXT_PUBLIC_PAYMENT_SECRET");

    const match = content.match(
      /NEXT_PUBLIC_PAYMENT_SECRET\s*=\s*["']?([^"'\s\n]+)["']?/
    );
    expect(match).toBeTruthy();
    const value = match![1].replace(/^["']|["']$/g, "").trim();
    expect(value).toBe(BASE64_SECRET);
    const decoded = decodeBase64(value);
    expect(decoded).toBe(FLAGS.PUBLIC_ENVIRONMENT_VARIABLE);
  });
});
