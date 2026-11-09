import { existsSync, readFileSync, statSync } from "fs";
import path from "path";
import { buildDataset, LEAKED_HUB_TOKEN } from "../../lib/hub-mirror";
import { FLAGS } from "../helpers/flags";
import { git } from "../helpers/git";

const ROOT = path.join(__dirname, "..", "..");

// gitleaks' huggingface-access-token rule.
const HF_TOKEN_LITERAL = /\bhf_[a-zA-Z]{34}(?:[`'"\s;]|\\[nr]|$)/m;

describe("LEAKED_HUB_TOKEN", () => {
  it("has the shape of a Hugging Face user access token", () => {
    expect(LEAKED_HUB_TOKEN).toMatch(HF_TOKEN_LITERAL);
  });

  it("keeps the prefix the walkthrough shows", () => {
    expect(LEAKED_HUB_TOKEN.startsWith("hf_SuRr")).toBe(true);
  });
});

describe("repository", () => {
  it("holds no Hugging Face token literal, which GitHub push protection would block", () => {
    const files = git(
      ROOT,
      "ls-files",
      "-z",
      "--cached",
      "--others",
      "--exclude-standard"
    )
      .split("\0")
      .map((file) => path.join(ROOT, file))
      .filter((file) => existsSync(file) && statSync(file).isFile());

    const offenders = files.filter((file) => {
      const content = readFileSync(file);
      return (
        !content.includes(0) && HF_TOKEN_LITERAL.test(content.toString("utf-8"))
      );
    });

    expect(offenders).toEqual([]);
  });
});

describe("buildDataset", () => {
  const dataset = buildDataset(FLAGS.EXPOSED_MCP_CONFIG);
  const file = (name: string) =>
    dataset.files.find(({ path }) => path === name)!.content.toString("utf-8");

  it("ships the Hub's default .gitattributes, byte for byte", () => {
    // Blob oid the Hub lists for the default file, e.g. in stanfordnlp/imdb.
    expect(
      dataset.files.find(({ path }) => path === ".gitattributes")?.oid
    ).toBe("957b2579c6ef20995a09efd9a17f8fd90606f5ed");
  });

  it("puts the flag in exactly one conversation of a valid JSONL split", () => {
    const records = file("data/train.jsonl")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));

    expect(
      records.filter((record) =>
        JSON.stringify(record).includes(FLAGS.EXPOSED_MCP_CONFIG)
      )
    ).toHaveLength(1);
  });
});
