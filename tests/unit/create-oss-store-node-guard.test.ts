import { spawnSync } from "child_process";
import { mkdtempSync, readFileSync } from "fs";
import os from "os";
import path from "path";

/**
 * npx does not enforce `engines`, so the bin script checks the running major
 * itself. It is the only thing standing between a user on an old Node and a
 * cryptic node-gyp failure halfway through the install, and nothing else in the
 * suite exercises it.
 */

const BIN = path.resolve(
  __dirname,
  "../../packages/create-oss-store/bin/create-oss-store.js"
);

/**
 * Every spawn runs from a throwaway directory. The bin clones a repository when
 * it is given no arguments, so a test that stopped short of `--help` would
 * otherwise drop a full checkout into the working tree.
 */
const SANDBOX = mkdtempSync(path.join(os.tmpdir(), "create-oss-store-guard-"));

/**
 * The guard compares `process.versions.node`, which is read-only on the real
 * process. Re-running the bin under a stub that redefines it is the only way to
 * observe the refusal without an old Node on the machine.
 */
function runWithNodeMajor(major: string, args: string[] = []) {
  const stub = `
    Object.defineProperty(process.versions, "node", {
      value: ${JSON.stringify(`${major}.0.0`)},
      configurable: true,
    });
    Object.defineProperty(process, "version", {
      value: ${JSON.stringify(`v${major}.0.0`)},
      configurable: true,
    });
    process.argv = [process.argv[0], ${JSON.stringify(BIN)}, ...${JSON.stringify(args)}];
    await import(${JSON.stringify(`file://${BIN}`)});
  `;
  return spawnSync(process.execPath, ["--input-type=module", "-e", stub], {
    cwd: SANDBOX,
    encoding: "utf8",
    timeout: 10000,
    killSignal: "SIGKILL",
  });
}

describe("create-oss-store Node version guard", () => {
  it("refuses to run on a Node older than engines.node", () => {
    // --help on every spawn, including the ones expected to be refused: the
    // guard runs before parseArgs, so the refusal is identical either way, and
    // no path can reach createOssStore and clone a repository if the guard
    // itself ever regresses.
    const result = runWithNodeMajor("20", ["--help"]);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("needs Node.js 22 or newer");
    expect(result.stderr).toContain("v20.0.0");
    // The refusal must be actionable, not just a rejection.
    expect(result.stderr).toContain("nvm install 22");
    expect(result.stderr).toContain("https://nodejs.org");
  });

  it("reads the floor from engines.node instead of a hardcoded number", () => {
    const { engines } = JSON.parse(
      readFileSync(
        path.resolve(__dirname, "../../packages/create-oss-store/package.json"),
        "utf-8"
      )
    );
    const major = Number(engines.node.match(/\d+/)![0]);

    expect(runWithNodeMajor(String(major - 1), ["--help"]).status).toBe(1);
    expect(runWithNodeMajor(String(major), ["--help"]).status).toBe(0);
  });

  it("runs normally on a supported Node", () => {
    // --help exits before any network or filesystem work, so this proves the
    // guard lets a supported runtime through without cloning anything.
    const result = spawnSync(process.execPath, [BIN, "--help"], {
      cwd: SANDBOX,
      encoding: "utf8",
      timeout: 10000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Usage: create-oss-store");
    expect(result.stderr).toBe("");
  });

  it("ships package.json in the published tarball, so the guard can read it", () => {
    // `files` does not list package.json, but npm always includes it. If that
    // ever changed, the guard would throw ENOENT on every install instead.
    const result = spawnSync(
      "npm",
      ["pack", "--dry-run", "--json", "--ignore-scripts"],
      {
        cwd: path.resolve(__dirname, "../../packages/create-oss-store"),
        encoding: "utf8",
        timeout: 60000,
      }
    );

    expect(result.status).toBe(0);
    const files = JSON.parse(result.stdout)[0].files.map(
      (file: { path: string }) => file.path
    );
    expect(files).toContain("package.json");
    expect(files).toContain("bin/create-oss-store.js");
  });
});
