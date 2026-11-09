import { execFileSync } from "child_process";
import { MCP_SESSION_HEADER, MCP_SESSION_VALUE } from "../../lib/mcp-constants";
import { BASE_URL } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const DATASET = "oopssec-store/support-chat-transcripts";

interface McpConfig {
  mcpServers: Record<
    string,
    { command: string; args: string[]; env?: Record<string, string> }
  >;
}

interface WhoAmI {
  name: string;
  orgs: { name: string }[];
  auth: {
    accessToken: {
      role: string;
      fineGrained: {
        scoped: { entity: { name: string }; permissions: string[] }[];
      };
    };
  };
}

/** What a player reads off the leaked file: the token and the Hub it talks to. */
async function leakedCredentials() {
  const config = (await (
    await fetch(`${BASE_URL}/.mcp.json`)
  ).json()) as McpConfig;
  const env = config.mcpServers["support-evals"].env!;
  return { endpoint: env.HF_ENDPOINT, token: env.HF_TOKEN };
}

describe("Exposed MCP config", () => {
  let endpoint: string;
  let token: string;
  const asOwner = () => ({ headers: { Authorization: `Bearer ${token}` } });

  beforeAll(async () => {
    ({ endpoint, token } = await leakedCredentials());
  });

  describe("discovery", () => {
    it("serves /.mcp.json as JSON that the nuclei vscode-mcp-json template flags", async () => {
      const response = await fetch(`${BASE_URL}/.mcp.json`);
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain(
        "application/json"
      );
      expect(body).toContain('"mcpServers": {');
      expect(body).toContain('"args":');
    });

    it("hands both MCP servers the same Hugging Face token, and names the Hub mirror", async () => {
      const config = (await (
        await fetch(`${BASE_URL}/.mcp.json`)
      ).json()) as McpConfig;

      expect(token).toMatch(/^hf_[A-Za-z]{34}$/);
      expect(config.mcpServers["hf-mcp-server"].env?.HF_TOKEN).toBe(token);
      expect(endpoint).toMatch(/\/hf-mirror$/);
    });

    it("never carries the internal MCP session, a shortcut to another flag", async () => {
      const body = await (await fetch(`${BASE_URL}/.mcp.json`)).text();

      expect(body.toLowerCase()).not.toContain(
        MCP_SESSION_HEADER.toLowerCase()
      );
      expect(body).not.toContain(MCP_SESSION_VALUE);
    });
  });

  describe("token triage", () => {
    it("tells who owns the token and what it is scoped to", async () => {
      const response = await fetch(`${endpoint}/api/whoami-v2`, asOwner());
      const whoami = (await response.json()) as WhoAmI;

      expect(response.status).toBe(200);
      expect(whoami.name).toBe("vdessendre");
      expect(whoami.orgs.map(({ name }) => name)).toContain("oopssec-store");
      expect(whoami.auth.accessToken.role).toBe("fineGrained");
      expect(whoami.auth.accessToken.fineGrained.scoped).toContainEqual({
        entity: expect.objectContaining({ name: DATASET, type: "dataset" }),
        permissions: ["repo.content.read"],
      });
    });

    it("answers an anonymous whoami the way the Hub does", async () => {
      const response = await fetch(`${endpoint}/api/whoami-v2`);

      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toMatch(/^Bearer /);
      expect(await response.json()).toEqual({
        error: "Invalid username or password.",
      });
    });

    it("lists the org's private dataset to the token only", async () => {
      const listing = `${endpoint}/api/datasets?author=oopssec-store`;

      const owner = (await (await fetch(listing, asOwner())).json()) as {
        id: string;
        private: boolean;
      }[];
      const anonymous = await (await fetch(listing)).json();

      expect(owner).toEqual([
        expect.objectContaining({ id: DATASET, private: true }),
      ]);
      expect(anonymous).toEqual([]);
    });
  });

  describe("private dataset", () => {
    const resolve = () =>
      `${endpoint}/datasets/${DATASET}/resolve/main/data/train.jsonl`;

    // httpx-based huggingface_hub sends `true`, the requests-based one (< 1.0) `True`.
    it.each(["true", "True"])(
      "lists nested files for recursive=%s, as snapshot_download asks",
      async (recursive) => {
        const response = await fetch(
          `${endpoint}/api/datasets/${DATASET}/tree/main?recursive=${recursive}&expand=false`,
          asOwner()
        );
        const entries = (await response.json()) as { path: string }[];

        expect(entries.map(({ path }) => path)).toEqual([
          "data",
          ".gitattributes",
          "README.md",
          "data/train.jsonl",
        ]);
      }
    );

    // The calls huggingface_hub 2.4.0 makes for `hf download`, in that order.
    it("answers each call of hf download with what the client reads", async () => {
      const get = async <T>(path: string) =>
        (await (await fetch(`${endpoint}${path}`, asOwner())).json()) as T;

      const info = await get<{
        sha: string;
        siblings: { rfilename: string }[];
      }>(`/api/datasets/${DATASET}`);
      const { sha } = await get<{ sha: string }>(
        `/api/datasets/${DATASET}/revision/main`
      );
      const tree = await get<{ path: string; oid: string; size: number }[]>(
        `/api/datasets/${DATASET}/tree/${sha}?recursive=true&expand=false`
      );
      const train = tree.find(({ path }) => path === "data/train.jsonl")!;

      expect(info.sha).toBe(sha);
      expect(info.siblings).toContainEqual({ rfilename: "data/train.jsonl" });

      const metadata = await fetch(
        `${endpoint}/datasets/${DATASET}/resolve/${sha}/data/train.jsonl`,
        { ...asOwner(), method: "HEAD", redirect: "manual" }
      );

      expect(metadata.status).toBe(307);
      expect(metadata.headers.get("x-repo-commit")).toBe(sha);
      expect(metadata.headers.get("x-linked-size")).toBe(String(train.size));
      expect(metadata.headers.get("x-linked-etag")).toBe(`"${train.oid}"`);

      const cache = new URL(metadata.headers.get("location")!, endpoint);
      const head = await fetch(cache, { ...asOwner(), method: "HEAD" });

      expect(head.status).toBe(200);
      expect(head.headers.get("content-length")).toBe(String(train.size));
      expect(head.headers.get("etag")).toBe(`"${train.oid}"`);

      const file = await fetch(cache, asOwner());

      expect(await file.text()).toContain(FLAGS.EXPOSED_MCP_CONFIG);
    });

    it("answers a revision it cannot fit in a header the way the Hub does", async () => {
      const response = await fetch(
        `${endpoint}/api/datasets/${DATASET}/revision/%C3%A9t%C3%A9%0D%0A%E2%9C%93`,
        asOwner()
      );

      expect(response.status).toBe(404);
      expect(response.headers.get("x-error-code")).toBe("RevisionNotFound");
      expect(response.headers.get("x-error-message")).toBe(
        "Invalid rev id: ete *"
      );
      expect(await response.json()).toEqual({
        error: "Invalid rev id: été\r\n✓",
      });
    });

    it("redirects resolve to resolve-cache like the Hub, and the file holds the flag", async () => {
      const redirect = await fetch(resolve(), {
        ...asOwner(),
        redirect: "manual",
      });
      const location = redirect.headers.get("location")!;

      expect(redirect.status).toBe(307);
      expect(location).toMatch(/^\/hf-mirror\/api\/resolve-cache\/datasets\//);
      expect(redirect.headers.get("x-repo-commit")).toMatch(/^[0-9a-f]{40}$/);

      const file = await fetch(new URL(location, endpoint), asOwner());

      expect(file.status).toBe(200);
      expect(await file.text()).toContain(FLAGS.EXPOSED_MCP_CONFIG);
    });

    it("refuses the dataset without the token", async () => {
      const response = await fetch(resolve());

      expect(response.status).toBe(401);
    });
  });

  describe("revocation", () => {
    let revoked = false;

    const revoke = (credentials: string[]) =>
      fetch(`${endpoint}/api/credentials/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentials }),
      });

    /** Replays the challenge data, then tells what the server under test answers. */
    async function replayChallengeData(): Promise<number> {
      execFileSync("npx", ["tsx", "prisma/upgrade.ts"], { stdio: "pipe" });
      return (await fetch(`${endpoint}/api/whoami-v2`, asOwner())).status;
    }

    // Skipped tests or a failure must not leave the lab's token revoked.
    afterAll(async () => {
      if (!revoked) return;
      const status = await replayChallengeData();
      if (status !== 200) {
        throw new Error(
          `The leaked token is still revoked on ${BASE_URL} (whoami-v2 answered ${status}): ` +
            "prisma/upgrade.ts replayed another database than the server's. " +
            "Run npm run db:upgrade where the server runs, or restart its Docker container."
        );
      }
    });

    it("answers 202 with an empty body for a token that does not exist", async () => {
      const response = await revoke([`hf_${"x".repeat(34)}`]);

      expect(response.status).toBe(202);
      expect(await response.text()).toBe("");
    });

    it("answers 202 for the leaked token, which then stops working everywhere", async () => {
      const response = await revoke([token]);
      revoked = true;

      expect(response.status).toBe(202);
      expect((await fetch(`${endpoint}/api/whoami-v2`, asOwner())).status).toBe(
        401
      );
      expect(
        (
          await fetch(
            `${endpoint}/datasets/${DATASET}/resolve/main/README.md`,
            asOwner()
          )
        ).status
      ).toBe(401);
    });

    it("works again once the challenge data is replayed", async () => {
      expect(await replayChallengeData()).toBe(200);
      revoked = false;
    });
  });
});
