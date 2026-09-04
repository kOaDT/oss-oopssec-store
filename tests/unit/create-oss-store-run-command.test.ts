import { spawnSync } from "child_process";
import path from "path";
import { pathToFileURL } from "url";

const runCommandUrl = pathToFileURL(
  path.resolve(__dirname, "../../packages/create-oss-store/src/run-command.js")
).href;

function runWithRunCommand(body: string, timeout = 8000) {
  const script = `
    import { runCommand } from ${JSON.stringify(runCommandUrl)};
    try {
      ${body}
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
  `;
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    timeout,
    killSignal: "SIGKILL",
  });
}

describe("create-oss-store runCommand", () => {
  it("includes stdout in the rejection when stderr is empty", () => {
    const result = runWithRunCommand(`
      try {
        await runCommand(
          process.execPath,
          [
            "-e",
            "process.stdout.write('Type error: cannot compile foo.ts'); process.exit(1)",
          ],
          process.cwd()
        );
        process.stdout.write("RESOLVED");
        process.exit(2);
      } catch (error) {
        process.stdout.write(error.message);
      }
    `);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Type error: cannot compile foo.ts");
    expect(result.stdout).not.toContain("Command failed with code 1");
  });

  it("still prefers stderr when both streams have output", () => {
    const result = runWithRunCommand(`
      try {
        await runCommand(
          process.execPath,
          [
            "-e",
            "process.stdout.write('build log'); process.stderr.write('real error'); process.exit(1)",
          ],
          process.cwd()
        );
        process.stdout.write("RESOLVED");
        process.exit(2);
      } catch (error) {
        process.stdout.write(error.message);
      }
    `);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("real error");
    expect(result.stdout).not.toContain("build log");
  });

  it("completes when the child writes more than 64KB to stdout", () => {
    // Node buffers unread stdout (~64KB) on top of the OS pipe (~64KB), so
    // 128KB can still complete. 2MB exceeds both and hangs without a consumer.
    const result = runWithRunCommand(
      `
      await runCommand(
        process.execPath,
        ["-e", "process.stdout.write('x'.repeat(2 * 1024 * 1024))"],
        process.cwd()
      );
      process.stdout.write("completed");
    `,
      5000
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("completed");
  });

  it("resolves when the command succeeds", () => {
    const result = runWithRunCommand(`
      await runCommand(
        process.execPath,
        ["-e", "process.exit(0)"],
        process.cwd()
      );
      process.stdout.write("ok");
    `);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("ok");
  });

  it("falls back to the exit code when both streams are empty", () => {
    const result = runWithRunCommand(`
      try {
        await runCommand(
          process.execPath,
          ["-e", "process.exit(1)"],
          process.cwd()
        );
        process.stdout.write("RESOLVED");
        process.exit(2);
      } catch (error) {
        process.stdout.write(error.message);
      }
    `);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("Command failed with code 1");
  });
});
