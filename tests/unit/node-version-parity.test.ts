import { readdirSync, readFileSync } from "fs";
import { join } from "path";

/**
 * The Node major is declared in half a dozen places that nothing links
 * together: `.nvmrc`, two `engines.node` fields, `@types/node`, the Dockerfile's
 * build arg and the docs. Bumping one and forgetting the rest fails nowhere:
 * the app boots, the image builds, only the promise of a single source of truth
 * quietly dies. This suite is that link.
 *
 * Two different questions are being answered, and conflating them is what makes
 * a parity suite turn into an obstacle:
 *
 * - `.nvmrc` says which major we develop and build images on.
 * - `engines.node` says the oldest major we still support. Users of
 *   `npx create-oss-store` are held to it, so moving the team to a newer major
 *   must not silently lock them out.
 *
 * So `.nvmrc` only has to be at least the floor, while everything describing the
 * floor to a user has to state it exactly.
 */

const ROOT = join(__dirname, "..", "..");
const read = (...segments: string[]) =>
  readFileSync(join(ROOT, ...segments), "utf-8");
const readJson = (...segments: string[]) => JSON.parse(read(...segments));

const NVMRC_RAW = read(".nvmrc");
const NVMRC = NVMRC_RAW.trim();

const CLI_PACKAGE = ["packages", "create-oss-store", "package.json"];
const CLI_README = ["packages", "create-oss-store", "README.md"];

/**
 * `.nvmrc` feeds `actions/setup-node`, which happily resolves aliases we cannot
 * derive a major from. Keeping the file to a plain version keeps every consumer
 * — including a human reading it — able to answer "which major is this?".
 */
const NVMRC_FORMAT = /^v?(\d+)(?:\.\d+)*$/;

const majorOf = (value: string, source: string): number => {
  const match = value.match(/\d+/);
  if (!match) {
    throw new Error(`${source} does not declare a Node major: "${value}"`);
  }
  return Number(match[0]);
};

describe("Node version parity", () => {
  /**
   * Read lazily: an alias like "lts/*" has no major to compare against, and
   * resolving it here would abort the whole suite before the format test below
   * got a chance to say why.
   */
  const devMajor = () => majorOf(NVMRC, ".nvmrc");
  const supportedMajor = () =>
    majorOf(readJson("package.json").engines.node, "package.json engines.node");

  it("keeps .nvmrc to a bare version, not an nvm alias", () => {
    // `node --version > .nvmrc` is the idiom nvm documents, and it writes
    // "v22.1.0". That is tolerated; "lts/*" and "latest" are not, because they
    // resolve to a different major over time without the file ever changing.
    expect(NVMRC).toMatch(NVMRC_FORMAT);
    expect(NVMRC_RAW).not.toContain("\r");
  });

  it("declares the same support floor in both package.json files", () => {
    // The CLI installs the app, so a user who clears one bar has to clear both.
    expect(
      majorOf(
        readJson(...CLI_PACKAGE).engines.node,
        "packages/create-oss-store/package.json engines.node"
      )
    ).toBe(supportedMajor());
  });

  it("develops on a major no older than the support floor", () => {
    // Deliberately >=, not ==. Moving .nvmrc to a newer major is a team choice;
    // dropping support for the old one is a breaking change for users, and it
    // should take editing engines.node to make it.
    expect(devMajor()).toBeGreaterThanOrEqual(supportedMajor());
  });

  it("matches the NODE_VERSION default in the Dockerfile", () => {
    // Strict, unlike the floor above: the image is what we develop against.
    // Without this default, `docker build .` and a plain `docker compose up`
    // both fail with "invalid reference format" — hence the default, hence this.
    const match = read("Dockerfile").match(/^ARG NODE_VERSION=(\S+)$/m);
    expect(match).not.toBeNull();
    expect(majorOf(match![1], "Dockerfile ARG NODE_VERSION")).toBe(devMajor());
  });

  it("types the runtime at the support floor, not above it", () => {
    // @types/node above the floor is how you end up shipping a call that does
    // not exist on the oldest Node the project claims to run on.
    const { devDependencies } = readJson("package.json");
    expect(
      majorOf(devDependencies["@types/node"], "devDependencies @types/node")
    ).toBe(supportedMajor());
  });

  it("states the support floor in the EDUCATORS.md requirements table", () => {
    expect(read("EDUCATORS.md")).toContain(`Node ${supportedMajor()}+`);
  });

  it("states the support floor in the create-oss-store README", () => {
    expect(read(...CLI_README)).toContain(`Node.js ${supportedMajor()}`);
  });

  it("never pins a Node version in a workflow", () => {
    // A literal here is the drift that started all this: CI would keep passing
    // on the old major long after .nvmrc moved on.
    const dir = join(ROOT, ".github", "workflows");
    const files = [
      ...readdirSync(dir).map((name) => join("workflows", name)),
      join("actions", "setup-project", "action.yml"),
    ];

    for (const file of files) {
      const contents = read(".github", file);
      if (!contents.includes("setup-node")) continue;
      expect(`${file}: ${contents}`).toContain('node-version-file: ".nvmrc"');
      expect(file + contents.match(/^\s*node-version:.*$/m)).toBe(
        file + "null"
      );
    }
  });
});
