import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { buildExposedRepository } from "@/lib/exposed-git-repository";

const PUBLIC_ROOT = "/.git/";
const LAST_MODIFIED = "15-Jan-2026 17:48";

const NOT_FOUND = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`;

/** Direct children of `directory` ("" or ending in "/"): size, or null for a subdirectory. */
function listChildren(
  repository: Map<string, Buffer>,
  directory: string
): Map<string, number | null> {
  const children = new Map<string, number | null>();
  for (const [path, content] of repository) {
    if (!path.startsWith(directory)) continue;
    const rest = path.slice(directory.length);
    const slash = rest.indexOf("/");
    if (slash === -1) children.set(rest, content.length);
    else children.set(rest.slice(0, slash + 1), null);
  }
  return children;
}

/** Mimics nginx `autoindex on`: directories first, then files, by name. */
function renderListing(
  directory: string,
  children: Map<string, number | null>
): string {
  const title = `Index of ${PUBLIC_ROOT}${directory}`;
  const rows = [...children]
    .sort(([a, aSize], [b, bSize]) => {
      if ((aSize === null) !== (bSize === null)) return aSize === null ? -1 : 1;
      return a < b ? -1 : 1;
    })
    .map(([name, size]) => {
      const padding = " ".repeat(Math.max(1, 51 - name.length));
      const column = String(size ?? "-").padStart(20);
      return `<a href="${name}">${name}</a>${padding}${LAST_MODIFIED}${column}\n`;
    });

  return `<html>
<head><title>${title}</title></head>
<body>
<h1>${title}</h1><hr><pre><a href="../">../</a>
${rows.join("")}</pre><hr></body>
</html>
`;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path?: string[] }> }
) {
  const { path = [] } = await params;
  const relative = path.join("/");

  const flag = await prisma.flag.findUnique({
    where: { slug: "exposed-git-repository" },
  });
  if (!flag) {
    throw new Error(
      "Flag exposed-git-repository is missing: seed the database"
    );
  }

  const repository = buildExposedRepository(flag.flag);

  const file = repository.get(relative);
  if (file) {
    return new NextResponse(new Uint8Array(file), {
      headers: { "Content-Type": "application/octet-stream" },
    });
  }

  const directory = relative === "" ? "" : `${relative}/`;
  const children = listChildren(repository, directory);
  if (children.size === 0) {
    return new NextResponse(NOT_FOUND, {
      status: 404,
      headers: { "Content-Type": "text/html" },
    });
  }

  // The rewrite keeps the requested pathname, trailing slash included.
  if (!request.nextUrl.pathname.endsWith("/")) {
    return NextResponse.redirect(
      new URL(`${PUBLIC_ROOT}${directory}`, request.url),
      301
    );
  }

  return new NextResponse(renderListing(directory, children), {
    headers: { "Content-Type": "text/html" },
  });
}
