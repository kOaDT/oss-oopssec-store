/**
 * GitHub serves every avatar from this one host. Pinning it here rather than at
 * each call site means the runner cannot be pointed elsewhere — not by a pull
 * request editing `hall-of-fame/data.json`, and not by an API response that
 * came back with something other than an avatar URL in it.
 */
const AVATAR_HOST = "avatars.githubusercontent.com";

/**
 * Refusing redirects keeps the host pin covering the request that is actually
 * made, and the cap bounds what a compromised response could hand the runner.
 */
const TIMEOUT_MS = 5_000;
const MAX_BYTES = 2 * 1024 * 1024;

/**
 * resvg reads a data URI, not a format string: an `image/svg+xml` avatar would
 * be re-parsed as markup inside the SVG satori produced.
 *
 * `image/gif` is left out for the opposite reason — resvg does not decode it
 * and does not say so, rasterising the avatar to fully transparent pixels. A
 * hole where a face should be reads as a broken card; refusing the type instead
 * hands the template its fallback, which does not.
 */
const TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

/**
 * An avatar as a data URI, or `null` if it could not be had safely.
 *
 * resvg cannot follow a remote `href`, so the image has to travel inside the
 * SVG satori hands over. Every failure mode — refusal, redirect, wrong type,
 * oversized body, silence — degrades to `null` rather than failing the build:
 * a template that has a fallback for a missing avatar still renders correctly,
 * and a flaky avatar CDN should not hold up a docs deploy.
 *
 * `pixels` should be twice the box the template draws, so the circle stays
 * sharp once the card is rasterised.
 */
export default async function fetchAvatarDataUri(
  avatarUrl: string,
  pixels: number
): Promise<string | null> {
  try {
    const url = new URL(avatarUrl);
    if (url.protocol !== "https:" || url.host !== AVATAR_HOST) return null;
    url.searchParams.set("s", String(pixels));

    const response = await fetch(url, {
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) return null;

    const type = (response.headers.get("content-type") ?? "image/png")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (!TYPES.has(type)) return null;

    const body = Buffer.from(await response.arrayBuffer());
    if (body.byteLength > MAX_BYTES) return null;

    return `data:${type};base64,${body.toString("base64")}`;
  } catch {
    return null;
  }
}

/**
 * The same fetch across a list, a few at a time.
 *
 * The contributors row draws everyone, so this is unbounded in the length of
 * the list but not in what it does at once: firing every request in parallel
 * would open one socket per contributor to the same CDN, which is how a well
 * behaved build starts looking like a burst to the host it depends on. Each
 * slot still fails independently — a `null` is one monogram, not a lost row.
 */
export async function fetchAvatarDataUris(
  urls: (string | null)[],
  pixels: number,
  concurrency = 8
): Promise<(string | null)[]> {
  const avatars: (string | null)[] = new Array(urls.length).fill(null);
  let next = 0;

  async function worker(): Promise<void> {
    while (next < urls.length) {
      const index = next++;
      const url = urls[index];
      if (url) avatars[index] = await fetchAvatarDataUri(url, pixels);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, urls.length) }, worker)
  );

  return avatars;
}
