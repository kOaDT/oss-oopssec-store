import { spawnSync } from "child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "fs";
import os from "os";
import path from "path";

/**
 * `npm run setup` is the manual install path, and npm only warns about
 * `engines`. Without a guard of its own, setup.sh installs on an old Node with
 * an EBADENGINE warning buried in the output, which the CLI refuses outright.
 *
 * The script is run from a throwaway copy with `node`, `npm` and `npx` stubbed
 * on the PATH: a regression would otherwise install dependencies, delete
 * prisma/dev.db and start the app from the real working tree.
 */

const ROOT = path.resolve(__dirname, "..", "..");
const REQUIRED_MAJOR = Number(
  JSON.parse(
    readFileSync(path.join(ROOT, "package.json"), "utf-8")
  ).engines.node.match(/\d+/)[0]
);

function runSetupWithNode(version: string) {
  const sandbox = mkdtempSync(path.join(os.tmpdir(), "setup-node-guard-"));
  mkdirSync(path.join(sandbox, "scripts"));
  copyFileSync(
    path.join(ROOT, "scripts", "setup.sh"),
    path.join(sandbox, "scripts", "setup.sh")
  );
  copyFileSync(
    path.join(ROOT, "package.json"),
    path.join(sandbox, "package.json")
  );

  const bin = path.join(sandbox, "bin");
  const calls = path.join(sandbox, "calls.log");
  mkdirSync(bin);
  const stub = (name: string, body: string) => {
    writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(path.join(bin, name), 0o755);
  };
  stub("node", `echo "${version}"`);
  for (const tool of ["npm", "npx", "xdg-open", "open"]) {
    stub(tool, `echo "${tool} $*" >> "${calls}"`);
  }

  const result = spawnSync("bash", ["scripts/setup.sh"], {
    cwd: sandbox,
    encoding: "utf8",
    env: { PATH: `${bin}:/usr/bin:/bin`, HOME: sandbox },
    timeout: 20000,
    killSignal: "SIGKILL",
  });

  return {
    ...result,
    calls: existsSync(calls) ? readFileSync(calls, "utf-8") : "",
    envCreated: existsSync(path.join(sandbox, ".env")),
  };
}

describe("npm run setup Node version guard", () => {
  it("refuses a Node older than engines.node before touching anything", () => {
    const result = runSetupWithNode(`v${REQUIRED_MAJOR - 2}.20.2`);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `needs Node.js ${REQUIRED_MAJOR} or newer, but this is v${REQUIRED_MAJOR - 2}.20.2`
    );
    expect(result.calls).toBe("");
    expect(result.envCreated).toBe(false);
  });

  it("proceeds with the install on the minimum supported major", () => {
    const result = runSetupWithNode(`v${REQUIRED_MAJOR}.0.0`);

    expect(result.status).toBe(0);
    expect(result.calls).toContain("npm install");
  });
});
