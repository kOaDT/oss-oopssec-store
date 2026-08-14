import { flags as seedFlags } from "../../prisma/flags";
import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

/**
 * The lab hands out flag values through the API, so the API is what has to
 * withhold them. Before this suite existed, `GET /api/flags` serialized the
 * whole `Flag` row: every value was downloadable unauthenticated, and the
 * entire CTF could be completed with one request plus one call per flag to
 * `/api/flags/verify`. The `/flags` board hid them client-side only, and every
 * `/vulnerabilities/<slug>` page carried its flag in the <title> tag.
 *
 * These tests pin the rule: a flag value leaves the server only once the
 * challenge behind it is solved. Both halves of that rule need a solve to be
 * observable, so the suite submits one itself rather than hoping another suite
 * ran first — `/api/flags/verify` is idempotent, so this is a no-op on a
 * database where the challenge is already recorded.
 *
 * What a payload is *allowed* to contain is derived from `prisma/flags.ts` and
 * the solve ledger at `/api/flags/progress`, never from the response under
 * test: an endpoint that leaks everything would otherwise widen its own
 * expectations and pass.
 */

const SOLVED = { slug: "react2shell", value: FLAGS.REACT2SHELL };

/**
 * Real flag values, from the seed the database is built from. Scanning for
 * these rather than for /OSS\{.*\}/ keeps the literal `OSS{...}` placeholders
 * the UI prints in its input hints from reading as leaks.
 */
const VALUE_BY_SLUG = new Map(seedFlags.map((f) => [f.slug, f.flag]));
const KNOWN_VALUES = seedFlags.map((f) => f.flag);

interface FlagSummary {
  id: string;
  flag: string | null;
  slug: string;
  cve: string | null;
  cwe: string | null;
  owasp: string | null;
  markdownFile: string;
  category: string;
  difficulty: string;
}

/** Every known flag value the payload carries, whether or not it belongs there. */
function valuesIn(payload: string): string[] {
  return KNOWN_VALUES.filter((value) => payload.includes(value));
}

describe("Flag disclosure", () => {
  let flags: FlagSummary[];
  let solvedSlugs: Set<string>;
  /** The only values any payload may carry, per the solve ledger. */
  let allowed: Set<string>;

  beforeAll(async () => {
    const { status, data } = await apiRequest<{ valid: boolean }>(
      "/api/flags/verify",
      { method: "POST", body: JSON.stringify({ flag: SOLVED.value }) }
    );
    expect(status).toBe(200);
    expect(data.valid).toBe(true);

    const [{ data: flagList }, { data: progress }] = await Promise.all([
      apiRequest<FlagSummary[]>("/api/flags"),
      apiRequest<{ foundFlags: Array<{ slug: string }> }>(
        "/api/flags/progress"
      ),
    ]);

    flags = flagList;
    solvedSlugs = new Set(progress.foundFlags.map((entry) => entry.slug));
    allowed = new Set(
      [...solvedSlugs]
        .map((slug) => VALUE_BY_SLUG.get(slug))
        .filter((value): value is string => value !== undefined)
    );
  });

  describe("GET /api/flags", () => {
    it("returns every challenge", () => {
      expect(flags).toHaveLength(seedFlags.length);
    });

    it("exposes the value of a solved challenge", () => {
      const solved = flags.find((flag) => flag.slug === SOLVED.slug);

      expect(solved?.flag).toBe(SOLVED.value);
    });

    it("withholds the value of every unsolved challenge", () => {
      const leaked = flags
        .filter((flag) => flag.flag !== null && !solvedSlugs.has(flag.slug))
        .map((flag) => flag.slug);

      expect(leaked).toEqual([]);
    });

    it("serializes no flag value beyond the solved ones", async () => {
      const { data } = await apiRequest<FlagSummary[]>("/api/flags");
      const unexpected = valuesIn(JSON.stringify(data)).filter(
        (value) => !allowed.has(value)
      );

      expect(unexpected).toEqual([]);
    });

    it("keeps the metadata the flags board renders", () => {
      for (const flag of flags) {
        expect(typeof flag.id).toBe("string");
        expect(typeof flag.slug).toBe("string");
        expect(typeof flag.markdownFile).toBe("string");
        expect(typeof flag.category).toBe("string");
        expect(typeof flag.difficulty).toBe("string");
      }
    });
  });

  describe("GET /api/flags/[slug]", () => {
    it("exposes the value of a solved challenge", async () => {
      const { status, data } = await apiRequest<FlagSummary>(
        `/api/flags/${SOLVED.slug}`
      );

      expect(status).toBe(200);
      expect(data.flag).toBe(SOLVED.value);
      expect(data.slug).toBe(SOLVED.slug);
    });

    it("withholds the value of an unsolved challenge but keeps its metadata", async () => {
      const unsolved = seedFlags.find((flag) => !solvedSlugs.has(flag.slug));

      if (!unsolved) {
        // Every challenge is solved in this database; nothing to withhold.
        return;
      }

      const { status, data } = await apiRequest<FlagSummary>(
        `/api/flags/${unsolved.slug}`
      );

      expect(status).toBe(200);
      expect(data.flag).toBeNull();
      expect(data.slug).toBe(unsolved.slug);
      expect(data.markdownFile).toBe(unsolved.markdownFile);
    });

    it("still 404s on an unknown slug", async () => {
      const { status } = await apiRequest("/api/flags/not-a-real-challenge");

      expect(status).toBe(404);
    });
  });

  describe("Rendered pages", () => {
    it("does not put a flag value in a vulnerability page <title>", async () => {
      // Deliberately the solved challenge: its value is the one the server is
      // willing to hand out, so it is where a title built from it would leak.
      const { data } = await apiRequest<string>(
        `/vulnerabilities/${SOLVED.slug}`
      );
      const title = /<title[^>]*>([^<]*)<\/title>/i.exec(data)?.[1] ?? "";

      expect(valuesIn(title)).toEqual([]);
    });

    it("ships only solved flag values in the /flags board HTML", async () => {
      const { data } = await apiRequest<string>("/flags");
      const rendered = valuesIn(data);

      // The solved one must be there, otherwise the check below proves nothing:
      // a board that rendered no value at all would satisfy it.
      expect(rendered).toContain(SOLVED.value);
      expect(rendered.filter((value) => !allowed.has(value))).toEqual([]);
    });
  });
});
