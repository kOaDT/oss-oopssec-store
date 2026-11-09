import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { parseBody } from "@/lib/validation";
import { revokeCredentialsSchema } from "@/lib/validation/schemas/hub";
import {
  DATASET_ID,
  LEAKED_HUB_TOKEN,
  MIRROR_PATH,
  WHOAMI,
  buildDataset,
  type HubDataset,
  type HubFile,
} from "@/lib/hub-mirror";

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

type Caller = "anonymous" | "authorized" | "rejected";

type Target =
  | { kind: "info"; repoId: string; rev: string }
  | { kind: "tree"; repoId: string; rev: string; dir: string }
  | { kind: "resolve"; repoId: string; rev: string; file: string }
  | { kind: "cache"; repoId: string; rev: string; file: string };

type HeaderMap = Record<string, string>;

const json = (body: unknown, status = 200, headers: HeaderMap = {}) =>
  new NextResponse(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });

const text = (body: string | Buffer, status: number, headers: HeaderMap = {}) =>
  new NextResponse(typeof body === "string" ? body : new Uint8Array(body), {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...headers },
  });

/**
 * How the Hub fits a message into a header: accents dropped, each run of
 * control characters turned into a space, any other non-ASCII character into `*`.
 */
const asHeaderValue = (message: string) =>
  message
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .replace(/\p{Cc}+/gu, " ")
    .replace(/[^ -~]/g, "*");

/** The Hub answers `/api/*` in JSON and file routes in plain text. */
function hubError(
  api: boolean,
  status: number,
  message: string,
  headers: HeaderMap = {}
) {
  const all = { "X-Error-Message": asHeaderValue(message), ...headers };
  return api
    ? json({ error: message }, status, all)
    : text(message, status, all);
}

const unauthorized = (api: boolean) =>
  hubError(api, 401, "Invalid username or password.", {
    "WWW-Authenticate":
      'Bearer realm="Authentication required", charset="UTF-8"',
  });

const notFound = (api: boolean) => hubError(api, 404, "Not Found");

const repoNotFound = (api: boolean) =>
  hubError(api, 404, "Repository not found", {
    "X-Error-Code": "RepoNotFound",
  });

const revisionNotFound = (api: boolean, rev: string) =>
  hubError(api, 404, `Invalid rev id: ${rev}`, {
    "X-Error-Code": "RevisionNotFound",
  });

const entryNotFound = (api: boolean, commit: string) =>
  hubError(api, 404, "Entry not found", {
    "X-Error-Code": "EntryNotFound",
    "X-Repo-Commit": commit,
  });

async function identify(request: NextRequest): Promise<Caller> {
  const authorization = request.headers.get("authorization");
  if (!authorization) return "anonymous";

  const token = authorization.replace(/^Bearer\s+/i, "");
  if (token !== LEAKED_HUB_TOKEN) return "rejected";

  const revoked = await prisma.revokedHubToken.findUnique({ where: { token } });
  return revoked ? "rejected" : "authorized";
}

function parseTarget(path: string[]): Target | null {
  if (path[0] === "api" && path[1] === "datasets" && path.length >= 4) {
    const [, , namespace, name, action, rev, ...rest] = path;
    const repoId = `${namespace}/${name}`;
    if (action === undefined) return { kind: "info", repoId, rev: "main" };
    if (action === "revision" && rev && rest.length === 0) {
      return { kind: "info", repoId, rev };
    }
    if (action === "tree" && rev) {
      return { kind: "tree", repoId, rev, dir: rest.join("/") };
    }
    return null;
  }

  if (path[0] === "datasets" && path[3] === "resolve" && path.length >= 6) {
    const [, namespace, name, , rev, ...file] = path;
    return {
      kind: "resolve",
      repoId: `${namespace}/${name}`,
      rev,
      file: file.join("/"),
    };
  }

  if (
    path[0] === "api" &&
    path[1] === "resolve-cache" &&
    path[2] === "datasets" &&
    path.length >= 7
  ) {
    const [, , , namespace, name, rev, ...file] = path;
    return {
      kind: "cache",
      repoId: `${namespace}/${name}`,
      rev,
      file: file.join("/"),
    };
  }

  return null;
}

async function loadDataset(): Promise<HubDataset> {
  const flag = await prisma.flag.findUnique({
    where: { slug: "exposed-mcp-config" },
  });
  if (!flag) {
    throw new Error("Flag exposed-mcp-config is missing: seed the database");
  }
  return buildDataset(flag.flag);
}

const treeEntry = ({ path, oid, content }: HubFile) => ({
  type: "file",
  oid,
  size: content.length,
  path,
});

/** Top level first, then nested files when `recursive`, as the Hub orders them. */
function tree(dataset: HubDataset, dir: string, recursive: boolean) {
  const nested = dataset.files
    .filter(({ path }) => path.startsWith("data/"))
    .map(treeEntry);

  if (dir === "") {
    return json([
      { type: "directory", oid: dataset.dataOid, size: 0, path: "data" },
      ...dataset.files.filter(({ path }) => !path.includes("/")).map(treeEntry),
      ...(recursive ? nested : []),
    ]);
  }
  if (dir === "data") return json(nested);
  return entryNotFound(true, dataset.commit);
}

function redirectToCache(dataset: HubDataset, rev: string, file: HubFile) {
  const original = `/datasets/${DATASET_ID}/resolve/${rev}/${file.path}`;
  const location =
    `${MIRROR_PATH}/api/resolve-cache/datasets/${DATASET_ID}/${dataset.commit}/${file.path}` +
    `?${encodeURIComponent(original)}=&etag=${encodeURIComponent(`"${file.oid}"`)}`;

  return text(`Temporary Redirect. Redirecting to ${location}`, 307, {
    Location: location,
    "X-Repo-Commit": dataset.commit,
    "X-Linked-Size": String(file.content.length),
    "X-Linked-Etag": `"${file.oid}"`,
  });
}

function serveFile(dataset: HubDataset, file: HubFile) {
  const name = file.path.split("/").at(-1)!;
  return text(file.content, 200, {
    "Content-Length": String(file.content.length),
    ETag: `"${file.oid}"`,
    "X-Repo-Commit": dataset.commit,
    "Accept-Ranges": "bytes",
    "Content-Disposition": `inline; filename*=UTF-8''${encodeURIComponent(name)}; filename="${name}";`,
  });
}

async function serveRepo(target: Target, query: URLSearchParams) {
  const api = target.kind === "info" || target.kind === "tree";
  if (target.repoId !== DATASET_ID) return repoNotFound(api);

  const dataset = await loadDataset();
  const revisions =
    target.kind === "cache" ? [dataset.commit] : ["main", dataset.commit];
  if (!revisions.includes(target.rev)) {
    return revisionNotFound(api, target.rev);
  }

  switch (target.kind) {
    case "info":
      return json(dataset.info);
    case "tree":
      // `requests`-based clients (huggingface_hub < 1.0) send Python's `True`.
      return tree(
        dataset,
        target.dir,
        query.get("recursive")?.toLowerCase() === "true"
      );
    case "resolve":
    case "cache": {
      const file = dataset.files.find(({ path }) => path === target.file);
      if (!file) return entryNotFound(false, dataset.commit);
      return target.kind === "resolve"
        ? redirectToCache(dataset, target.rev, file)
        : serveFile(dataset, file);
    }
  }
}

function matchesListing(params: URLSearchParams): boolean {
  const author = params.get("author");
  const search = params.get("search");
  return (
    (!author || author === "oopssec-store") &&
    (!search || DATASET_ID.includes(search))
  );
}

export async function GET(request: NextRequest, { params }: RouteContext) {
  const { path } = await params;
  const api = path[0] === "api";
  const caller = await identify(request);
  if (caller === "rejected") return unauthorized(api);

  const route = path.join("/");
  if (route === "api/whoami-v2") {
    return caller === "authorized" ? json(WHOAMI) : unauthorized(true);
  }
  if (route === "api/datasets") {
    const visible =
      caller === "authorized" && matchesListing(request.nextUrl.searchParams);
    return json(visible ? [(await loadDataset()).listing] : []);
  }

  if (caller === "anonymous") return unauthorized(api);
  const target = parseTarget(path);
  if (!target) return notFound(api);
  return serveRepo(target, request.nextUrl.searchParams);
}

export async function POST(request: NextRequest, { params }: RouteContext) {
  const { path } = await params;
  if (path.join("/") !== "api/credentials/revoke") {
    return notFound(path[0] === "api");
  }

  const body = await parseBody(request, revokeCredentialsSchema);
  if (!body.success) return body.response;

  if (body.data.credentials.includes(LEAKED_HUB_TOKEN)) {
    await prisma.revokedHubToken.upsert({
      where: { token: LEAKED_HUB_TOKEN },
      update: {},
      create: { token: LEAKED_HUB_TOKEN },
    });
  }

  return new NextResponse(null, { status: 202 });
}
