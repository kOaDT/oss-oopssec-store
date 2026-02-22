import * as fs from "fs";
import * as path from "path";
import { FLAGS } from "../helpers/flags";

const FLAG_ENV_VAR = "FLAG_CVE_2025_55182";

describe("React 19 RCE (CVE-2025-55182) – Configuration", () => {
  it("dependencies.react is 19.2.0 or matches ^19", () => {
    const pkgPath = path.join(process.cwd(), "package.json");
    expect(fs.existsSync(pkgPath)).toBe(true);

    const content = fs.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(content) as { dependencies?: { react?: string } };
    expect(pkg.dependencies).toBeDefined();
    expect(pkg.dependencies!.react).toBeDefined();

    const reactVersion = pkg.dependencies!.react as string;
    expect(reactVersion).toBe("19.2.0");
    expect(reactVersion.startsWith("19")).toBe(true);
  });

  it('.env.local contains FLAG_CVE_2025_55182="OSS{r3act2sh3ll}"', () => {
    const envPath = path.join(process.cwd(), ".env.local");
    expect(fs.existsSync(envPath)).toBe(true);

    const content = fs.readFileSync(envPath, "utf-8");
    expect(content).toContain(FLAG_ENV_VAR);
    expect(content).toContain(FLAGS.REACT2SHELL);
  });
});
