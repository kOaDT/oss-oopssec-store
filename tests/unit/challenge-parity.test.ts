import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import { flags, flagHints } from "../../prisma/flags";
import { CURRICULUM, TOTAL_CHALLENGES } from "../../docs/src/data/roadmap";
import { CATEGORY_LABELS } from "../../lib/format";
import { FLAGS } from "../helpers/flags";

/**
 * Adding a challenge means touching a dozen files across the app, the docs site
 * and the marketing copy. Nothing else fails when one of them is forgotten:
 * the app reads its totals from the database, and the docs site only validates
 * `walkthroughSlug`. This suite is the safety net — every failure message names
 * the file left behind.
 *
 * See the "Adding a challenge" checklist in CONTRIBUTING.md.
 */

const ROOT = join(__dirname, "..", "..");
const read = (...segments: string[]) =>
  readFileSync(join(ROOT, ...segments), "utf-8");

const CHALLENGES = CURRICULUM.flatMap((chapter) =>
  chapter.challenges.map((challenge) => ({
    ...challenge,
    chapterTitle: chapter.title,
  }))
);

const DIFFICULTY_EMOJI: Record<string, string> = {
  EASY: "🟢",
  MEDIUM: "🟡",
  HARD: "🔴",
};

/** Renders `estimatedMinutes` the way the EDUCATORS.md catalog spells it. */
function formatEstimate([min, max]: [number, number | null]): string {
  if (max === null) return `${min}+ min`;
  return min === max ? `${min} min` : `${min}–${max} min`;
}

/** Markdown table rows following the header line that starts with `marker`. */
function tableRows(markdown: string, marker: string): string[][] {
  const lines = markdown.split("\n");
  const header = lines.findIndex((line) => line.startsWith(marker));
  expect(header).toBeGreaterThan(-1);

  const rows: string[][] = [];
  for (let i = header + 2; i < lines.length && lines[i].startsWith("|"); i++) {
    rows.push(
      lines[i]
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim())
    );
  }
  return rows;
}

describe("prisma/flags.ts", () => {
  it("uses the OSS{...} format with unique values and kebab-case slugs", () => {
    for (const { flag, slug } of flags) {
      expect(flag).toMatch(/^OSS\{[^{}]+\}$/);
      expect(slug).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
    }

    expect(new Set(flags.map((f) => f.flag)).size).toBe(flags.length);
    expect(new Set(flags.map((f) => f.slug)).size).toBe(flags.length);
  });

  it("only uses categories declared in the Prisma schema", () => {
    const schema = read("prisma", "schema.prisma");
    const block = schema.match(/enum FlagCategory \{([^}]*)\}/);
    expect(block).not.toBeNull();

    const declared = block![1].trim().split(/\s+/);
    for (const { slug, category } of flags) {
      expect([slug, declared.includes(category)]).toEqual([slug, true]);
    }

    // A new category needs a human-readable label, or the UI renders nothing.
    expect(Object.keys(CATEGORY_LABELS).sort()).toEqual([...declared].sort());
  });

  it("tags CVE, CWE and OWASP identifiers in a linkable format", () => {
    for (const { slug, cve, cwe, owasp } of flags) {
      if (cve)
        expect([slug, cve]).toEqual([
          slug,
          expect.stringMatching(/^CVE-\d{4}-\d{4,}$/),
        ]);
      if (cwe)
        expect([slug, cwe]).toEqual([slug, expect.stringMatching(/^CWE-\d+$/)]);
      if (owasp)
        expect([slug, owasp]).toEqual([
          slug,
          expect.stringMatching(/^A\d{2}:(2021|2025)$/),
        ]);
    }
  });
});

describe("content/vulnerabilities", () => {
  const files = readdirSync(join(ROOT, "content", "vulnerabilities")).filter(
    (file) => file.endsWith(".md")
  );

  it("has the reference doc every flag points at, and no orphan file", () => {
    const referenced = flags.map((f) => f.markdownFile);

    for (const { slug, markdownFile } of flags) {
      expect([slug, files.includes(markdownFile)]).toEqual([slug, true]);
    }

    const orphans = files.filter((file) => !referenced.includes(file));
    expect(orphans).toEqual([]);
  });

  it("never spoils a flag value (those belong in the walkthrough)", () => {
    const values = flags.map((f) => f.flag);

    for (const file of files) {
      const content = read("content", "vulnerabilities", file);
      const leaked = values.filter((value) => content.includes(value));
      expect([file, leaked]).toEqual([file, []]);
    }
  });
});

describe("hints", () => {
  it("gives every flag exactly three non-empty progressive hints", () => {
    for (const { slug } of flags) {
      const hints = flagHints[slug];
      expect([slug, hints?.length]).toEqual([slug, 3]);
      for (const hint of hints) {
        expect([slug, hint.trim().length > 0]).toEqual([slug, true]);
      }
    }
  });

  it("never spoils a flag value (level 3 is near-solution, not the answer)", () => {
    const values = flags.map((f) => f.flag);

    for (const [slug, hints] of Object.entries(flagHints)) {
      hints.forEach((hint, index) => {
        const leaked = values.filter((value) => hint.includes(value));
        expect([slug, index + 1, leaked]).toEqual([slug, index + 1, []]);
      });
    }
  });

  it("has no hints keyed on an unknown slug", () => {
    const slugs = flags.map((f) => f.slug);
    const unknown = Object.keys(flagHints).filter(
      (slug) => !slugs.includes(slug)
    );
    expect(unknown).toEqual([]);
  });
});

describe("tests/helpers/flags.ts", () => {
  it("mirrors every flag value so exploitation tests can assert on it", () => {
    const known = Object.values(FLAGS) as string[];
    const missing = flags
      .filter((f) => !known.includes(f.flag))
      .map((f) => f.slug);
    expect(missing).toEqual([]);
  });

  it("declares no flag value that the seed no longer contains", () => {
    const values = flags.map((f) => f.flag);
    const stale = Object.entries(FLAGS)
      .filter(([, value]) => !values.includes(value))
      .map(([name]) => name);
    expect(stale).toEqual([]);
  });
});

describe("docs/src/data/roadmap.ts", () => {
  it("covers every flag exactly once", () => {
    expect(TOTAL_CHALLENGES).toBe(flags.length);
    expect(CHALLENGES.map((c) => c.slug).sort()).toEqual(
      flags.map((f) => f.slug).sort()
    );
  });

  it("agrees with the seed on difficulty, category and walkthrough", () => {
    for (const challenge of CHALLENGES) {
      const flag = flags.find((f) => f.slug === challenge.slug);
      expect([challenge.slug, flag]).not.toEqual([challenge.slug, undefined]);
      expect([challenge.slug, challenge.difficulty]).toEqual([
        challenge.slug,
        flag!.difficulty,
      ]);
      expect([challenge.slug, challenge.category]).toEqual([
        challenge.slug,
        flag!.category,
      ]);
      expect([challenge.slug, challenge.walkthroughSlug]).toEqual([
        challenge.slug,
        flag!.walkthroughSlug,
      ]);
    }
  });

  it("points every walkthroughSlug at an existing post", () => {
    /* Astro's glob loader ids a post by its frontmatter `slug` when present,
     * and by its file name otherwise. `walkthroughSlug` matches that id, not
     * necessarily the file on disk. */
    const posts = readdirSync(join(ROOT, "docs", "src", "data", "blog"))
      .filter((file) => file.endsWith(".md"))
      .map((file) => {
        const frontmatter = read("docs", "src", "data", "blog", file);
        const override = frontmatter.match(/^slug: (.+)$/m);
        return override ? override[1].trim() : file.replace(/\.md$/, "");
      });

    for (const { slug, walkthroughSlug } of CHALLENGES) {
      expect([slug, posts.includes(walkthroughSlug)]).toEqual([slug, true]);
    }
  });

  it("only lists prerequisites that exist and come earlier", () => {
    CHALLENGES.forEach((challenge, index) => {
      for (const prerequisite of challenge.prerequisites ?? []) {
        expect([challenge.slug, prerequisite]).toEqual([
          challenge.slug,
          expect.any(Number),
        ]);
        expect(prerequisite).toBeGreaterThan(0);
        expect(prerequisite).toBeLessThan(index + 1);
      }
    });
  });
});

describe("README.md", () => {
  const readme = read("README.md");

  it("advertises the current challenge and chapter counts", () => {
    const feature = readme.match(/(\d+) CTF challenges across (\d+) chapters/);
    expect(feature).not.toBeNull();
    expect(Number(feature![1])).toBe(flags.length);
    expect(Number(feature![2])).toBe(CURRICULUM.length);

    const comparison = readme.match(/(\d+) chapters, (\d+) flags/);
    expect(comparison).not.toBeNull();
    expect(Number(comparison![1])).toBe(CURRICULUM.length);
    expect(Number(comparison![2])).toBe(flags.length);
  });
});

describe("EDUCATORS.md", () => {
  const educators = read("EDUCATORS.md");

  it("advertises the current challenge and chapter counts", () => {
    const intro = educators.match(/all (\d+) challenges/);
    expect(intro).not.toBeNull();
    expect(Number(intro![1])).toBe(flags.length);

    const chapters = educators.match(/grouped into (\d+) thematic chapters/);
    expect(chapters).not.toBeNull();
    expect(Number(chapters![1])).toBe(CURRICULUM.length);
  });

  it("keeps the challenge catalog in sync with the roadmap", () => {
    const rows = tableRows(educators, "| #   | Challenge");
    expect(rows).toHaveLength(CHALLENGES.length);

    rows.forEach(([number, title, chapter, category, difficulty, time], i) => {
      const challenge = CHALLENGES[i];
      expect([title, Number(number)]).toEqual([title, i + 1]);
      expect([challenge.slug, title]).toEqual([
        challenge.slug,
        challenge.title,
      ]);
      expect([challenge.slug, chapter]).toEqual([
        challenge.slug,
        challenge.chapterTitle,
      ]);
      expect([challenge.slug, category]).toEqual([
        challenge.slug,
        CATEGORY_LABELS[challenge.category],
      ]);
      expect([challenge.slug, difficulty]).toEqual([
        challenge.slug,
        DIFFICULTY_EMOJI[challenge.difficulty],
      ]);
      expect([challenge.slug, time]).toEqual([
        challenge.slug,
        formatEstimate(challenge.estimatedMinutes),
      ]);
    });
  });

  it("lists every challenge in the OWASP coverage grid", () => {
    const rows = tableRows(educators, "| OWASP Category");
    expect(rows.length).toBeGreaterThan(0);

    const covered = rows.map(([category]) =>
      category.replace(/\*\*/g, "").trim()
    );
    for (const { slug, owasp } of flags) {
      if (!owasp) continue;
      const code = owasp.slice(0, 3);
      const line = covered.find((entry) => entry.startsWith(`${code} -`));
      expect([slug, owasp, line]).not.toEqual([slug, owasp, undefined]);
    }
  });
});
