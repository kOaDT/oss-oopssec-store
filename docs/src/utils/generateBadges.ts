import cardBadge from "./badge-templates/card";
import pillBadge from "./badge-templates/pill";
import type { HallOfFameEntry } from "./getHallOfFame";
import { svgBufferToPngBuffer } from "./svgToPng";

/** Twice the rendered avatar box, so the circle stays sharp on the card. */
const AVATAR_PIXELS = "240";

/** The avatar host is pinned by `assertValid`, but the pin only covers the URL
 * we are handed. Refusing redirects keeps it covering the request that is
 * actually made, and the cap bounds what a compromised response could hand the
 * runner. */
const AVATAR_TIMEOUT_MS = 5_000;
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;

/** resvg reads a data URI, not a format string: an `image/svg+xml` avatar
 * would be re-parsed as markup inside the SVG satori produced. */
const AVATAR_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "long",
  day: "numeric",
  timeZone: "UTC",
});

/**
 * resvg cannot follow a remote `href`, so the avatar has to travel inside the
 * SVG satori hands over. Every failure mode — refusal, redirect, wrong type,
 * oversized body, silence — degrades to the monogram fallback rather than
 * failing the build: the badge still reads correctly, and a flaky avatar CDN
 * should not hold up a docs deploy.
 */
async function fetchAvatar(entry: HallOfFameEntry): Promise<string | null> {
  try {
    const url = new URL(entry.avatarUrl);
    url.searchParams.set("s", AVATAR_PIXELS);

    const response = await fetch(url, {
      redirect: "error",
      signal: AbortSignal.timeout(AVATAR_TIMEOUT_MS),
    });
    if (!response.ok) return null;

    const type = (response.headers.get("content-type") ?? "image/png")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (!AVATAR_TYPES.has(type)) return null;

    const body = Buffer.from(await response.arrayBuffer());
    if (body.byteLength > AVATAR_MAX_BYTES) return null;

    return `data:${type};base64,${body.toString("base64")}`;
  } catch {
    return null;
  }
}

/** The inline pill, as a self-contained SVG (satori draws glyphs as paths). */
export function generateBadgePill(entry: HallOfFameEntry): Promise<string> {
  return pillBadge(entry);
}

/** The 1200x630 social card, rasterised for platforms that reject SVG. */
export async function generateBadgeCard(
  entry: HallOfFameEntry
): Promise<Uint8Array<ArrayBuffer>> {
  const svg = await cardBadge(entry, {
    avatar: await fetchAvatar(entry),
    formattedDate: dateFormatter.format(new Date(entry.date)),
  });

  return svgBufferToPngBuffer(svg);
}
