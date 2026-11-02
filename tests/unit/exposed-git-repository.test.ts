import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import os from "os";
import path from "path";
import {
  buildExposedRepository,
  hashObject,
  HEAD_COMMIT,
} from "../../lib/exposed-git-repository";
import { FLAGS } from "../helpers/flags";
import { findDroppedStashes, git, readCommittedFile } from "../helpers/git";

const FLAG = FLAGS.EXPOSED_GIT_REPOSITORY;

describe("hashObject", () => {
  it("hashes a blob the way git hash-object does", () => {
    expect(hashObject("blob", "hello\n")).toBe(
      "ce013625030ba8dba906f756967f9e9ca394464a"
    );
  });
});

describe("buildExposedRepository", () => {
  const repository = buildExposedRepository(FLAG);
  let workTree: string;

  beforeAll(() => {
    workTree = mkdtempSync(path.join(os.tmpdir(), "oopssec-exposed-git-"));
    for (const [file, content] of repository) {
      const target = path.join(workTree, ".git", file);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, content);
    }
  });

  afterAll(() => {
    rmSync(workTree, { recursive: true, force: true });
  });

  it("writes a repository that git fsck --full accepts", () => {
    expect(() => git(workTree, "fsck", "--full", "--strict")).not.toThrow();
  });

  it("checks out main at the commit the footer advertises", () => {
    expect(git(workTree, "rev-parse", "HEAD").trim()).toBe(HEAD_COMMIT);
  });

  // A dumper's final `git checkout .` restores the working tree from this index.
  it("ships an index identical to HEAD", () => {
    expect(() =>
      git(workTree, "diff", "--cached", "--exit-code", "--quiet")
    ).not.toThrow();
    expect(git(workTree, "ls-files").trim().split("\n")).toEqual([
      ".gitignore",
      "README.md",
      "next.config.js",
      "package.json",
      "theme/tokens.css",
    ]);
  });

  it("leaves exactly one dropped stash for the git-stash recovery recipe", () => {
    expect(findDroppedStashes(workTree)).toHaveLength(1);
  });

  it("keeps the flag in the .env.production of that stash", () => {
    const [stash] = findDroppedStashes(workTree);

    expect(readCommittedFile(workTree, stash, ".env.production")).toContain(
      `INTERNAL_API_TOKEN=${FLAG}`
    );
  });

  it("only carries the flag inside zlib-compressed objects", () => {
    const leaking = [...repository]
      .filter(([, content]) => content.includes(FLAG))
      .map(([file]) => file);

    expect(leaking).toEqual([]);
  });
});
