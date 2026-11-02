import { createHash } from "crypto";
import { deflateSync } from "zlib";

type ObjectType = "blob" | "tree" | "commit";

/** Uncompressed objects keyed by SHA-1, header included. */
type ObjectStore = Map<string, Buffer>;

type Snapshot = Record<string, string>;

interface CommitSpec {
  tree: string;
  parents: string[];
  timestamp: number;
  message: string;
}

const DEVELOPER = "Renoir Dessendre <renoir.dessendre@oss.com>";
const TIMEZONE = "+0100";
const STASHED_AT = 1768495690;

const GITIGNORE = `node_modules/
.next/
.env
.env.local
`;

const README_INITIAL = `# OopsSec Store storefront

Customer-facing storefront, built with Next.js.

## Development

    npm install
    npm run dev
`;

const README_DEPLOY = `${README_INITIAL}
## Deployment

    npm run build
    rsync -az ./ deploy@web-01:/var/www/storefront/
`;

const THEME_TOKENS = `:root {
  --color-primary: #4f46e5;
  --color-surface: #ffffff;
  --radius-card: 0.75rem;
}
`;

const NEXT_CONFIG = `/** @type {import('next').NextConfig} */
module.exports = {
  output: "standalone",
};
`;

const PACKAGE_JSON = `{
  "name": "oopssec-storefront",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  }
}
`;

const INITIAL_FILES: Snapshot = {
  ".gitignore": GITIGNORE,
  "README.md": README_INITIAL,
};
const THEMED_FILES: Snapshot = {
  ...INITIAL_FILES,
  "theme/tokens.css": THEME_TOKENS,
};
const RELEASED_FILES: Snapshot = {
  ...THEMED_FILES,
  "README.md": README_DEPLOY,
  "next.config.js": NEXT_CONFIG,
  "package.json": PACKAGE_JSON,
};

const HISTORY = [
  { message: "Initial commit", timestamp: 1768205642, files: INITIAL_FILES },
  {
    message: "Add storefront theme",
    timestamp: 1768318851,
    files: THEMED_FILES,
  },
  {
    message: "Configure production build",
    timestamp: 1768471357,
    files: RELEASED_FILES,
  },
];

const CONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
`;

const DESCRIPTION =
  "Unnamed repository; edit this file 'description' to name the repository.\n";

function envProduction(flag: string): string {
  return `# Production only. Never commit this file.
NODE_ENV=production
DATABASE_URL=postgres://storefront@db.oopssec.internal:5432/storefront
INTERNAL_API_TOKEN=${flag}
`;
}

function sha1(data: Buffer): string {
  return createHash("sha1").update(data).digest("hex");
}

function encodeObject(type: ObjectType, content: Buffer | string) {
  const body = typeof content === "string" ? Buffer.from(content) : content;
  const encoded = Buffer.concat([
    Buffer.from(`${type} ${body.length}\0`),
    body,
  ]);
  return { sha: sha1(encoded), encoded };
}

export function hashObject(type: ObjectType, content: Buffer | string): string {
  return encodeObject(type, content).sha;
}

function writeObject(
  store: ObjectStore,
  type: ObjectType,
  content: Buffer | string
): string {
  const { sha, encoded } = encodeObject(type, content);
  store.set(sha, encoded);
  return sha;
}

function writeTree(store: ObjectStore, files: Snapshot): string {
  const blobs = new Map<string, string>();
  const subdirectories = new Map<string, Snapshot>();

  for (const [path, content] of Object.entries(files)) {
    const slash = path.indexOf("/");
    if (slash === -1) {
      blobs.set(path, writeObject(store, "blob", content));
      continue;
    }
    const directory = path.slice(0, slash);
    const nested = subdirectories.get(directory) ?? {};
    nested[path.slice(slash + 1)] = content;
    subdirectories.set(directory, nested);
  }

  // Git sorts a subtree as if its name ended with "/".
  const entries = [
    ...[...blobs].map(([name, sha]) => ({
      mode: "100644",
      name,
      sha,
      key: name,
    })),
    ...[...subdirectories].map(([name, nested]) => ({
      mode: "40000",
      name,
      sha: writeTree(store, nested),
      key: `${name}/`,
    })),
  ].sort((a, b) => Buffer.compare(Buffer.from(a.key), Buffer.from(b.key)));

  return writeObject(
    store,
    "tree",
    Buffer.concat(
      entries.flatMap(({ mode, name, sha }) => [
        Buffer.from(`${mode} ${name}\0`),
        Buffer.from(sha, "hex"),
      ])
    )
  );
}

function writeCommit(
  store: ObjectStore,
  { tree, parents, timestamp, message }: CommitSpec
): string {
  const signature = `${DEVELOPER} ${timestamp} ${TIMEZONE}`;
  const lines = [
    `tree ${tree}`,
    ...parents.map((parent) => `parent ${parent}`),
    `author ${signature}`,
    `committer ${signature}`,
    "",
    message,
  ];
  return writeObject(store, "commit", `${lines.join("\n")}\n`);
}

function writeHistory(store: ObjectStore): string[] {
  const commits: string[] = [];
  for (const { message, timestamp, files } of HISTORY) {
    commits.push(
      writeCommit(store, {
        tree: writeTree(store, files),
        parents: commits.slice(-1),
        timestamp,
        message,
      })
    );
  }
  return commits;
}

function reflog(commits: string[]): string {
  return commits
    .map((sha, i) => {
      const previous = i === 0 ? "0".repeat(40) : commits[i - 1];
      const action = i === 0 ? "commit (initial)" : "commit";
      const { message, timestamp } = HISTORY[i];
      return `${previous} ${sha} ${DEVELOPER} ${timestamp} ${TIMEZONE}\t${action}: ${message}\n`;
    })
    .join("");
}

/** DIRC version 2, as `git stash` leaves it: every entry matches HEAD. */
function buildIndex(files: Snapshot): Buffer {
  const paths = Object.keys(files).sort((a, b) =>
    Buffer.compare(Buffer.from(a), Buffer.from(b))
  );

  const header = Buffer.alloc(12);
  header.write("DIRC", 0, "ascii");
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(paths.length, 8);

  const entries = paths.map((path) => {
    const content = Buffer.from(files[path]);
    const name = Buffer.from(path);
    // 62 fixed bytes, then the path, NUL-padded to a multiple of 8 (at least one NUL).
    const entry = Buffer.alloc((62 + name.length + 8) & ~7);
    entry.writeUInt32BE(STASHED_AT, 0);
    entry.writeUInt32BE(STASHED_AT, 8);
    entry.writeUInt32BE(0o100644, 24);
    entry.writeUInt32BE(content.length, 36);
    Buffer.from(hashObject("blob", content), "hex").copy(entry, 40);
    entry.writeUInt16BE(Math.min(name.length, 0xfff), 60);
    name.copy(entry, 62);
    return entry;
  });

  const body = Buffer.concat([header, ...entries]);
  return Buffer.concat([body, Buffer.from(sha1(body), "hex")]);
}

/** The tip of `main`. The visible history never contains the flag. */
export const HEAD_COMMIT = writeHistory(new Map()).at(-1)!;

/**
 * Every file of the exposed `.git`, keyed by its path inside it. The stash is
 * shaped as `git stash` writes it, then dropped: only its loose objects remain.
 */
export function buildExposedRepository(flag: string): Map<string, Buffer> {
  const store: ObjectStore = new Map();
  const commits = writeHistory(store);
  const head = commits.at(-1)!;
  const { message: subject, files } = HISTORY.at(-1)!;

  const stashedTree = writeTree(store, {
    ...files,
    ".env.production": envProduction(flag),
  });
  const reference = `${head.slice(0, 7)} ${subject}`;
  const indexCommit = writeCommit(store, {
    tree: stashedTree,
    parents: [head],
    timestamp: STASHED_AT,
    message: `index on main: ${reference}`,
  });
  writeCommit(store, {
    tree: stashedTree,
    parents: [head, indexCommit],
    timestamp: STASHED_AT,
    message: `WIP on main: ${reference}`,
  });

  const repository = new Map<string, Buffer>([
    ["HEAD", Buffer.from("ref: refs/heads/main\n")],
    ["config", Buffer.from(CONFIG)],
    ["description", Buffer.from(DESCRIPTION)],
    ["COMMIT_EDITMSG", Buffer.from(`${subject}\n`)],
    ["index", buildIndex(files)],
    ["refs/heads/main", Buffer.from(`${head}\n`)],
    ["logs/HEAD", Buffer.from(reflog(commits))],
    ["logs/refs/heads/main", Buffer.from(reflog(commits))],
  ]);
  for (const [sha, encoded] of store) {
    repository.set(
      `objects/${sha.slice(0, 2)}/${sha.slice(2)}`,
      deflateSync(encoded)
    );
  }
  return repository;
}
