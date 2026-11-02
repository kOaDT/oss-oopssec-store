import { execFileSync } from "child_process";

// GIT_DIR or GIT_INDEX_FILE inherited from a git hook would point git at another repository.
const ENV = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_"))
  ),
  LC_ALL: "C",
};

/** Runs git in `cwd` with English messages: fsck output is parsed by position. */
export function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: ENV,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/** The git-stash docs' recovery recipe: unreachable merges saying WIP. */
export function findDroppedStashes(cwd: string): string[] {
  const unreachable = git(cwd, "fsck", "--unreachable")
    .split("\n")
    .filter((line) => line.startsWith("unreachable commit "))
    .map((line) => line.split(" ")[2]);
  // Given no revision, git log would fall back to HEAD.
  if (unreachable.length === 0) return [];

  return git(
    cwd,
    "log",
    "--merges",
    "--no-walk",
    "--grep=WIP",
    "--format=%H",
    ...unreachable
  )
    .split("\n")
    .filter(Boolean);
}

/** Reads a top-level file of `commit`: commit → tree → blob, via cat-file. */
export function readCommittedFile(
  cwd: string,
  commit: string,
  name: string
): string {
  const tree = /^tree ([0-9a-f]{40})$/m.exec(
    git(cwd, "cat-file", "-p", commit)
  )?.[1];
  if (!tree) throw new Error(`${commit} has no tree line`);

  const entry = git(cwd, "cat-file", "-p", tree)
    .split("\n")
    .map((line) => line.split("\t"))
    .find(([, path]) => path === name);
  if (!entry) throw new Error(`${name} is not in the tree of ${commit}`);

  const [mode, type, blob] = entry[0].split(" ");
  if (mode !== "100644" || type !== "blob") {
    throw new Error(`${name} in ${commit} is a ${mode} ${type}, not a file`);
  }
  return git(cwd, "cat-file", "-p", blob);
}
