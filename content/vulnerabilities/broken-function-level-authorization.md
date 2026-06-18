# Broken Function Level Authorization (Live Stream Hijack)

## Overview

Broken Function Level Authorization (BFLA) happens when an API authenticates the caller but never checks that the caller's **role** is allowed to invoke a privileged function. Authentication ("who are you?") is solved; the function-level authorization ("are you allowed to _perform this action_?") is missing. The privileged action is hidden in the UI for non-admins, and developers mistake that cosmetic gating for real access control.

In this challenge, OopsSec Store runs **OopsSec Live**, a live-shopping stream whose featured video is controlled from an admin "Stream Management" panel. The panel only renders its controls for administrators, which makes the feature look access-controlled. The API that backs it tells a different story: it authenticates the caller but does not verify that they are an administrator before letting them change the broadcast.

This is the same failure mode behind the 2026 FIFA internal-systems breach, where the Angular frontend read a `NO_ROLES` marker from the JWT and rendered an access-denied page while the backend APIs checked nothing. That exposed two things at once: privileged write operations (match scores, lineups, kick-off times) reachable by any authenticated account, and the broadcast's RTMP ingest keys sitting in the URL — the same pair this challenge reproduces with an unprotected `POST` and a leaky `GET`.

## Why This Is Dangerous

- **Hiding a button is not authorization** — client-side role checks are trivially bypassed by calling the API directly; the server is the only place authorization counts.
- **Privileged action from an unprivileged account** — any authenticated customer performs an admin-only operation, no escalation needed.
- **Broadcast / content integrity** — an attacker controls what every visitor sees on the public live page, enabling defacement, scams, or reputational damage.
- **Exposed operational controls** — the same endpoint leaks the RTMP ingest URL and stream key, handing over the broadcast pipeline itself.

## Vulnerable Code

```typescript
// app/api/live/stream/route.ts
export const GET = withAuth(async (_request, _context, _user) => {
  const config = await prisma.streamConfig.findFirst();
  return NextResponse.json(config); // leaks rtmpUrl + streamKey to any logged-in user
});

export const POST = withAuth(async (request, _context, user) => {
  const { liveVideoId } = await request.json();

  const updated = await prisma.streamConfig.update({
    where: { id: 1 },
    data: { liveVideoId },
  });

  // The UI only shows the "Update stream" button to admins, so the developer
  // assumed only admins reach this code. Nothing here checks user.role.
  return NextResponse.json({ ok: true, config: updated });
});
```

`withAuth` proves the caller has a valid session, but it says nothing about their role. The admin-only intent lives entirely in the React component that hides the button — the server happily accepts a `liveVideoId` from any authenticated customer.

## Secure Implementation

Enforce the role on the server, inside the handler, independently of the UI. The codebase already ships a `withAdminAuth` wrapper for exactly this — function-level authorization belongs on every privileged route, not just the ones a non-admin "shouldn't" find.

```typescript
// app/api/live/stream/route.ts
export const POST = withAdminAuth(async (request, _context, _user) => {
  const { liveVideoId } = await request.json();

  // Validate the input too: only accept a known-good YouTube video ID format,
  // never a free-form URL the client controls.
  if (!/^[A-Za-z0-9_-]{11}$/.test(liveVideoId)) {
    return NextResponse.json({ error: "Invalid video id" }, { status: 400 });
  }

  const updated = await prisma.streamConfig.update({
    where: { id: 1 },
    data: { liveVideoId },
  });

  return NextResponse.json({ ok: true, config: updated });
});
```

Treat secrets as secrets, too: the RTMP ingest URL and stream key should never be returned to a normal user session — scope them to admin reads (or drop them from the response entirely). The principle is the same as for object-level checks — authorization is enforced by the handler, not by whether the client chose to show a button.

## References

- [OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Top 10 — A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [How we accidentally hacked FIFA — bobdahacker.com](https://bobdahacker.com/blog/fifa-hack)
