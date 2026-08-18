import { readFileSync } from "fs";
import { join } from "path";
import {
  badgeSlug,
  parseHallOfFame,
  type HallOfFameEntry,
} from "../../docs/src/utils/getHallOfFame";
import { badgeUrls } from "../../lib/config";

/**
 * The badge pipeline is the one place where a pull request from a stranger
 * decides what a CI runner fetches and what gets published under a real
 * person's name. `parseHallOfFame` is the only thing standing there, and the
 * slug it produces is duplicated in `lib/config.ts` so the app can build the
 * URLs without importing the docs project. Nothing else holds those two
 * together, or checks that the guards actually reject what they claim to.
 *
 * See the "Hall of Fame" section in CONTRIBUTING.md.
 */

const ROOT = join(__dirname, "..", "..");

const VALID: HallOfFameEntry = {
  username: "kOaDT",
  avatarUrl: "https://avatars.githubusercontent.com/u/17499022?v=4",
  githubUrl: "https://github.com/kOaDT",
  date: "2026-01-16",
  country: "France",
};

const entry = (overrides: Partial<Record<keyof HallOfFameEntry, unknown>>) => [
  { ...VALID, ...overrides },
];

describe("hall-of-fame/data.json", () => {
  it("passes the validation the docs build applies", () => {
    const raw: unknown = JSON.parse(
      readFileSync(join(ROOT, "hall-of-fame", "data.json"), "utf8")
    );

    const entries = parseHallOfFame(raw);
    expect(entries.length).toBeGreaterThan(0);
  });

  it("rejects a payload that is not an array", () => {
    expect(() => parseHallOfFame({ username: "kOaDT" })).toThrow(
      "expected an array"
    );
  });
});

describe("avatar host allowlist", () => {
  it("accepts an avatar served by GitHub", () => {
    expect(parseHallOfFame(entry({}))).toHaveLength(1);
  });

  it.each([
    ["a host of the contributor's choosing", "https://evil.example.com/a.png"],
    [
      "a lookalike subdomain",
      "https://avatars.githubusercontent.com.evil.tld/a.png",
    ],
    [
      "plain http on the right host",
      "http://avatars.githubusercontent.com/u/1",
    ],
  ])("rejects %s", (_label, avatarUrl) => {
    expect(() => parseHallOfFame(entry({ avatarUrl }))).toThrow(
      "avatarUrl must be served by avatars.githubusercontent.com"
    );
  });

  it("rejects a profile URL that is not on github.com", () => {
    expect(() =>
      parseHallOfFame(entry({ githubUrl: "https://gitlab.com/kOaDT" }))
    ).toThrow("githubUrl must point at https://github.com");
  });

  it("rejects a relative URL", () => {
    expect(() => parseHallOfFame(entry({ avatarUrl: "/avatar.png" }))).toThrow(
      "must be absolute URLs"
    );
  });
});

describe("username validation", () => {
  it.each([
    ["the maximum GitHub length", "a".repeat(39)],
    ["a single inner hyphen", "kO-aDT"],
    ["digits only", "1337"],
  ])("accepts %s", (_label, username) => {
    expect(parseHallOfFame(entry({ username }))).toHaveLength(1);
  });

  it.each([
    ["one character over the limit", "a".repeat(40)],
    // The bound has to count hyphens: a pattern that pairs each hyphen with the
    // character after it lets this 77-character username through.
    ["a hyphenated name past the limit", "a" + "-b".repeat(38)],
    ["consecutive hyphens", "a--b"],
    ["a leading hyphen", "-abc"],
    ["a trailing hyphen", "abc-"],
    ["a path traversal attempt", "../../etc/passwd"],
    ["an empty string", ""],
  ])("rejects %s", (_label, username) => {
    expect(() => parseHallOfFame(entry({ username }))).toThrow(
      "is not a valid GitHub username"
    );
  });
});

describe("badge slug", () => {
  it("refuses two usernames that differ only in case", () => {
    expect(() =>
      parseHallOfFame([
        VALID,
        { ...VALID, username: "koadt", githubUrl: "https://github.com/koadt" },
      ])
    ).toThrow('collide on the badge slug "koadt"');
  });

  /**
   * `badgeUrls` cannot import `badgeSlug`: it ships in the Next app, and the
   * docs module reads the filesystem. This is what keeps the copy honest.
   */
  it.each(["kOaDT", "ALLCAPS", "mixed-Case-99", "a".repeat(39)])(
    "agrees with badgeUrls for %s",
    (username) => {
      const slug = badgeSlug(username);
      const { pill, card } = badgeUrls(username);

      expect(pill).toBe(
        `https://koadt.github.io/oss-oopssec-store/badges/${slug}.svg`
      );
      expect(card).toBe(
        `https://koadt.github.io/oss-oopssec-store/badges/${slug}.png`
      );
    }
  );
});
