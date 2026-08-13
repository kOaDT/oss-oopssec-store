#!/usr/bin/env node
/**
 * Regenerates the GitHub Discussion forms that carry a per-challenge dropdown.
 *
 * The dropdown is the tagging convention the community pages rely on: every
 * question asked from the lab records which challenge it belongs to, in a shape
 * that can be parsed back out of the discussion body. Without it there is no way
 * to attach a thread to its walkthrough.
 *
 * Source of truth is `docs/src/data/roadmap.ts` — the same curriculum that feeds
 * the roadmap page and `challenges.json`. Re-run this after adding a challenge:
 *
 *   npm run discussions:templates
 */

import { readFile, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROADMAP = join(ROOT, "docs", "src", "data", "roadmap.ts");
const OUT_DIR = join(ROOT, ".github", "DISCUSSION_TEMPLATE");

/** Minimum plausible curriculum size. Guards against the parser silently
 * matching nothing if `roadmap.ts` is ever reformatted. */
const MIN_CHALLENGES = 30;

async function readCurriculum() {
  const src = await readFile(ROADMAP, "utf8");
  const challenges = [
    ...src.matchAll(/title:\s*"([^"]+)",\s*\n\s*slug:\s*"([^"]+)"/g),
  ].map(([, title, slug]) => ({ title, slug }));

  if (challenges.length < MIN_CHALLENGES) {
    throw new Error(
      `Parsed only ${challenges.length} challenges from roadmap.ts (expected ` +
        `at least ${MIN_CHALLENGES}). The file layout probably changed — fix ` +
        `the regex in ${import.meta.url}.`
    );
  }

  return challenges;
}

/** Renders one dropdown option. The slug goes last, in parentheses, so the
 * label stays readable while a parser can recover the join key with
 * `/\(([a-z0-9-]+)\)$/`.
 *
 * Quoted via `JSON.stringify` rather than by hand: a title containing a double
 * quote would otherwise close the YAML scalar early and produce a file GitHub
 * refuses to parse, with nothing in this pipeline to catch it. JSON string
 * syntax is a subset of YAML's double-quoted scalar, so the escapes round-trip
 * exactly. */
const option = ({ title, slug }) =>
  `        - ${JSON.stringify(`${title} (${slug})`)}`;

const dropdown = (challenges) =>
  `  - type: dropdown
    id: challenge
    attributes:
      label: Which challenge?
      description: Pick the challenge this thread is about.
      options:
${challenges.map(option).join("\n")}
    validations:
      required: true`;

const stuck = (challenges) => `title: "[Stuck] "
labels: ["community"]
body:
  - type: markdown
    attributes:
      value: |
        **Spoilers are welcome here.** Every flag is in the source code and
        there is nothing to win by finishing first, so post real payloads,
        real output, and real solutions. Vague hints help nobody.

${dropdown(challenges)}
  - type: textarea
    id: goal
    attributes:
      label: What are you trying to do?
      description: The step you are on, and what you expected to happen.
      placeholder: I am trying to forge the share token, and I expected the API to accept it.
    validations:
      required: true
  - type: textarea
    id: attempts
    attributes:
      label: What have you tried?
      description: Payloads, requests, tooling. Paste the actual commands.
      render: shell
    validations:
      required: true
  - type: textarea
    id: result
    attributes:
      label: What happened instead?
      description: The exact response, error, or status code you get.
      render: shell
    validations:
      required: true
  - type: input
    id: environment
    attributes:
      label: How are you running the lab?
      description: npx / Docker / manual clone, plus your Node version.
      placeholder: "Docker, image tag latest"
    validations:
      required: false
`;

const solve = (challenges) => `title: "[Solve] "
labels: ["community"]
body:
  - type: markdown
    attributes:
      value: |
        Post the full solution. Alternative routes to the same flag are the most
        useful thing you can share here — they are what the walkthroughs miss.

${dropdown(challenges)}
  - type: textarea
    id: approach
    attributes:
      label: How did you solve it?
      description: The reasoning, not just the payload. What made you look there?
    validations:
      required: true
  - type: textarea
    id: payload
    attributes:
      label: Payload or script
      render: shell
    validations:
      required: false
  - type: textarea
    id: different
    attributes:
      label: How does this differ from the published walkthrough?
      description: Leave blank if you followed the same route.
    validations:
      required: false
`;

const TEMPLATES = {
  "stuck-on-a-challenge.yml": stuck,
  "show-your-solve.yml": solve,
};

const challenges = await readCurriculum();

for (const [name, render] of Object.entries(TEMPLATES)) {
  await writeFile(join(OUT_DIR, name), render(challenges), "utf8");
  console.log(`wrote .github/DISCUSSION_TEMPLATE/${name}`);
}

console.log(`${challenges.length} challenges in the dropdown.`);
