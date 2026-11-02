import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import os from "os";
import path from "path";
import { apiRequest, BASE_URL } from "../helpers/api";
import { FLAGS } from "../helpers/flags";
import { findDroppedStashes, git, readCommittedFile } from "../helpers/git";

function linksIn(listing: string): string[] {
  return [...listing.matchAll(/<a href="([^"]+)">/g)]
    .map(([, href]) => href)
    .filter((href) => href !== "../");
}

/** Follows the autoindex pages the way git-dumper and `wget -r -np` do. */
async function mirror(directory: string, root: string): Promise<void> {
  const listing = await fetch(`${BASE_URL}/.git/${directory}`, {
    redirect: "manual",
  });
  if (listing.status !== 200) {
    throw new Error(`/.git/${directory} answered ${listing.status}`);
  }

  for (const href of linksIn(await listing.text())) {
    // Links come from the server under test: never write outside the temp dir.
    const local = path.resolve(root, directory, href);
    if (!local.startsWith(root + path.sep)) {
      throw new Error(`/.git/${directory} links outside the repo: ${href}`);
    }

    if (href.endsWith("/")) {
      await mirror(`${directory}${href}`, root);
      continue;
    }
    const response = await fetch(`${BASE_URL}/.git/${directory}${href}`);
    if (response.status !== 200) {
      throw new Error(`/.git/${directory}${href} answered ${response.status}`);
    }
    mkdirSync(path.dirname(local), { recursive: true });
    writeFileSync(local, Buffer.from(await response.arrayBuffer()));
  }
}

describe("Exposed .git repository", () => {
  describe("discovery", () => {
    it("serves /.git/ as a directory listing, without redirecting", async () => {
      const { status, headers, data } = await apiRequest<string>("/.git/", {
        redirect: "manual",
      });

      expect(status).toBe(200);
      expect(headers.get("content-type")).toContain("text/html");
      expect(linksIn(data)).toContain("HEAD");
    });

    it.each([
      ["/.git", "/.git/"],
      ["/.git/objects", "/.git/objects/"],
    ])(
      "redirects %s to its slashed URL, as nginx does",
      async (requested, location) => {
        const { status, headers } = await apiRequest(requested, {
          redirect: "manual",
        });

        expect(status).toBe(301);
        expect(new URL(headers.get("location")!, BASE_URL).pathname).toBe(
          location
        );
      }
    );

    it("advertises the deployed commit in the footer", async () => {
      const { data: home } = await apiRequest<string>("/");
      const build = /build ([0-9a-f]{7})/.exec(
        home.replace(/<!-- -->/g, "")
      )?.[1];
      const { data: head } = await apiRequest<string>("/.git/refs/heads/main");

      expect(build).toBeDefined();
      expect(head.startsWith(build!)).toBe(true);
    });
  });

  describe("dumped repository", () => {
    let workTree: string;
    let stashes: string[];

    beforeAll(async () => {
      workTree = mkdtempSync(path.join(os.tmpdir(), "oopssec-git-dump-"));
      await mirror("", path.join(workTree, ".git"));
      stashes = findDroppedStashes(workTree);
    });

    afterAll(() => {
      rmSync(workTree, { recursive: true, force: true });
    });

    it("finds the dropped stash among unreachable commits", () => {
      expect(stashes).toHaveLength(1);
    });

    it("keeps the stash out of git log --all and refs/stash", () => {
      const reachable = git(workTree, "log", "--all", "--format=%H");

      expect(reachable.split("\n")).not.toContain(stashes[0]);
      expect(git(workTree, "for-each-ref", "refs/stash")).toBe("");
    });

    it("yields the flag from the stashed .env.production", () => {
      expect(
        readCommittedFile(workTree, stashes[0], ".env.production")
      ).toContain(`INTERNAL_API_TOKEN=${FLAGS.EXPOSED_GIT_REPOSITORY}`);
    });
  });
});
