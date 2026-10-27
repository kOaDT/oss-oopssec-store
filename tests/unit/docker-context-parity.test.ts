import { execFileSync } from "child_process";
import { readFileSync } from "fs";
import { join } from "path";

/**
 * The published image builds from a Git context, which BuildKit never filters
 * through `.dockerignore`, while a local build does. A tracked path excluded in
 * one place only ships in one image and not the other, and nothing else
 * notices: both images build and start. This suite keeps the two lists in step.
 */

const ROOT = join(__dirname, "..", "..");
const read = (...segments: string[]) =>
  readFileSync(join(ROOT, ...segments), "utf-8");

const DOCKERFILE = read("Dockerfile");
const IGNORE_ENTRIES = read(".dockerignore")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line !== "" && !line.startsWith("#"));

const isTracked = (path: string) =>
  execFileSync("git", ["ls-files", "--", path], {
    cwd: ROOT,
    encoding: "utf-8",
  }).trim() !== "";

describe("Docker context parity", () => {
  it("excludes from the image every tracked path the local context leaves out", () => {
    const excluded = [...DOCKERFILE.matchAll(/--exclude=(\S+)/g)].map(
      (match) => match[1]
    );
    const missing = IGNORE_ENTRIES.filter((entry) => !entry.startsWith("!"))
      .map((entry) => entry.replace(/\/$/, ""))
      .filter((entry) => isTracked(entry) && !excluded.includes(entry));
    expect(missing).toEqual([]);
  });

  it("copies into the image every tracked path the local context re-includes", () => {
    const missing = IGNORE_ENTRIES.filter((entry) => entry.startsWith("!"))
      .map((entry) => entry.slice(1))
      .filter(
        (entry) =>
          isTracked(entry) &&
          !DOCKERFILE.split("\n").some((line) =>
            line.startsWith(`COPY ${entry} `)
          )
      );
    expect(missing).toEqual([]);
  });
});
