# Exposed .git Repository

## Overview

A Git working copy keeps its whole history in a `.git` directory at its root. When a deployment copies the working copy instead of a build artifact, that directory lands in the web root, and a web server that serves static files serves it too: `HEAD`, refs, reflogs, the index and every object.

In this challenge, the storefront was deployed with an `rsync` of the developer's checkout to a server running nginx with `autoindex on`. The visible history is clean. The secret sits in a stash the developer created and then dropped, which Git no longer lists anywhere but has not deleted.

## Why This Is Dangerous

- **Full source disclosure**: the repository turns a black-box target into a white-box one. Routes, internal endpoints, validation logic and hardcoded credentials all become readable.
- **Secrets in history**: a secret removed in a later commit is still in the objects of the earlier one. Deleting a file does not delete its past.
- **Metadata for recon**: commit authors, email addresses, internal hostnames and deployment commands give an attacker names to phish and hosts to target.
- **Dropping a stash does not erase it**: `git stash drop` deletes a reference, not the commits behind it. Those commits become unreachable loose objects and stay on disk until `git gc` prunes them, after a two-week grace period by default. A deployment server rarely runs `gc` at all.
- **Listing is not even required**: with directory listing off, tools still rebuild the reachable history from well-known paths (`HEAD`, `refs/heads/*`, `logs/HEAD`) and the object paths derived from each SHA-1. Listing only makes the unreachable objects visible too.

## Vulnerable Code

The deployment copies the checkout as-is, `.git` included:

```bash
npm run build
rsync -az ./ deploy@web-01:/var/www/storefront/
```

And the web server serves everything under the web root, with directory listing on:

```nginx
server {
    listen 80;
    root /var/www/storefront;
    autoindex on;
}
```

These two snippets belong to the scenario, not to this repository. OopsSec Store runs on Next.js, and a route handler plays the part of that nginx server under `/.git/`, serving a repository it generates in memory.

## Secure Implementation

**Never deploy a working copy.** Ship a build artifact: the output of CI, a container image built with `.git` in `.dockerignore`, or `git archive` of a tagged commit. If you must sync a directory, exclude version-control data explicitly:

```bash
rsync -az --exclude='.git' ./ deploy@web-01:/var/www/storefront/
```

**Block dotfiles at the reverse proxy.** Answer 404 for any path segment starting with a dot, keep `.well-known` reachable for ACME and `security.txt`, and leave directory listing off:

```nginx
autoindex off;

location ^~ /.well-known/ {
}

location ~ /\. {
    return 404;
}
```

**Rotate the secret first.** Anything that was ever reachable under `/.git/` must be treated as published. Cleaning up afterwards does not un-leak it.

**Purge unreachable objects from repositories you keep.** Expire the reflog entries that still point at them, then prune without the grace period:

```bash
git reflog expire --expire-unreachable=now --all
git gc --prune=now
```

If the secret reached a commit that was pushed, rewriting history (for example with `git filter-repo`) is also needed on every clone, which is one more reason to rotate rather than rely on cleanup.

**Stop secrets before they are committed.** Ignore environment files by pattern (`.env*`, with an explicit `!.env.example` exception) instead of listing them one by one, and run a secret scanner such as gitleaks as a pre-commit hook and in CI.

## References

- [CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/527.html)
- [OWASP Top 10 — A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [git-stash documentation](https://git-scm.com/docs/git-stash)
- [git-gc documentation](https://git-scm.com/docs/git-gc)
- [git-reflog documentation](https://git-scm.com/docs/git-reflog)
- [nginx ngx_http_autoindex_module](https://nginx.org/en/docs/http/ngx_http_autoindex_module.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
