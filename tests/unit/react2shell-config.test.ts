import * as fs from "fs";
import * as path from "path";
import { FLAGS } from "../helpers/flags";

/**
 * The pins that keep the challenge reproducible. What actually proves the
 * deserializer is still exploitable lives in
 * tests/unit/react2shell-flight-deserializer.test.ts.
 */

const AFFECTED_REACT_VERSION = "19.2.0";
const FLAG_ENV_VAR = "FLAG_CVE_2025_55182";

describe("React 19 RCE (CVE-2025-55182) – Configuration", () => {
  it("pins react and react-dom to an affected version", () => {
    const pkgPath = path.join(process.cwd(), "package.json");
    expect(fs.existsSync(pkgPath)).toBe(true);

    const content = fs.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(content) as {
      dependencies?: Record<string, string>;
    };
    expect(pkg.dependencies).toBeDefined();

    expect(pkg.dependencies!.react).toBe(AFFECTED_REACT_VERSION);
    expect(pkg.dependencies!["react-dom"]).toBe(AFFECTED_REACT_VERSION);
  });

  it('.env.local contains FLAG_CVE_2025_55182="OSS{r3act2sh3ll}"', () => {
    const envPath = path.join(process.cwd(), ".env.local");
    expect(fs.existsSync(envPath)).toBe(true);

    const content = fs.readFileSync(envPath, "utf-8");
    expect(content).toContain(FLAG_ENV_VAR);
    expect(content).toContain(FLAGS.REACT2SHELL);
  });
});
