# Path Traversal

## Overview

Path traversal happens when a server builds a filesystem path by joining a base directory with a user-controlled string and reads from the result without verifying that the resolved path stays inside the base. Sequences like `../` walk up the directory tree, escaping the intended sandbox and exposing arbitrary files.

In this challenge, the document API (`GET /api/files?file=…` and a directory-listing variant) joins the `documents/` base directory with the `file` query parameter and reads whatever path that produces.

## Why This Is Dangerous

- **Source and config disclosure** — `../.env`, `../package.json`, application source, and database backups become readable.
- **System file access** — on Linux, `/etc/passwd`, `/proc/*`, and other readable system files are reachable.
- **Credential leakage** — environment files and config files routinely hold secrets.
- **Pivoting** — leaked secrets often enable further attacks (cloud credentials, API keys, JWT signing keys).

## Vulnerable Code

```typescript
const baseDir = join(process.cwd(), "documents");

if (!file) {
  return NextResponse.json(
    { error: "File parameter is required" },
    { status: 400 }
  );
}

const filePath = join(baseDir, file);
const content = await readFile(filePath, "utf-8");

return NextResponse.json({ filename: file, content });
```

`path.join` collapses `..` segments but does not constrain the result to `baseDir`. With `file = "../flag.txt"`, the resolved path lands outside `documents/` and `readFile` happily returns its content.

## Secure Implementation

Resolve the candidate path and verify, after normalization, that it is still under the trusted base directory:

```typescript
import path from "path";

const baseDir = path.resolve(process.cwd(), "documents");
const requested = path.resolve(baseDir, file);

if (!requested.startsWith(baseDir + path.sep)) {
  return NextResponse.json({ error: "Invalid path" }, { status: 400 });
}

const content = await readFile(requested, "utf-8");
```

For stronger guarantees, prefer an explicit allowlist or an indirect identifier:

```typescript
const ALLOWED_FILES: Record<string, string> = {
  "terms-of-service": "terms.md",
  "privacy-policy": "privacy.md",
};

const filename = ALLOWED_FILES[slug];
if (!filename) {
  return NextResponse.json({ error: "Not found" }, { status: 404 });
}
const content = await readFile(path.join(baseDir, filename), "utf-8");
```

Two more guardrails worth applying at every layer that touches user-supplied paths:

- Reject any input containing `..`, `\`, NUL bytes, or absolute paths before joining.
- Run the application under a user that has read access only to the directories it actually needs.

## References

- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger — Path traversal](https://portswigger.net/web-security/file-path-traversal)
- [Node.js `path.resolve`](https://nodejs.org/api/path.html#pathresolvepaths)
