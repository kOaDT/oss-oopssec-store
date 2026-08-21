import cardBadge from "./badge-templates/card";
import pillBadge from "./badge-templates/pill";
import fetchAvatarDataUri from "./fetchAvatarDataUri";
import type { HallOfFameEntry } from "./getHallOfFame";
import { svgBufferToPngBuffer } from "./svgToPng";

/** Twice the rendered avatar box, so the circle stays sharp on the card. */
const AVATAR_PIXELS = 240;

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "long",
  day: "numeric",
  timeZone: "UTC",
});

/** The inline pill, as a self-contained SVG (satori draws glyphs as paths). */
export function generateBadgePill(entry: HallOfFameEntry): Promise<string> {
  return pillBadge(entry);
}

/** The 1200x630 social card, rasterised for platforms that reject SVG. */
export async function generateBadgeCard(
  entry: HallOfFameEntry
): Promise<Uint8Array<ArrayBuffer>> {
  const svg = await cardBadge(entry, {
    avatar: await fetchAvatarDataUri(entry.avatarUrl, AVATAR_PIXELS),
    formattedDate: dateFormatter.format(new Date(entry.date)),
  });

  return svgBufferToPngBuffer(svg);
}
