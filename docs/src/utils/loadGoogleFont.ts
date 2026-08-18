interface LoadedFont {
  name: string;
  data: ArrayBuffer;
  weight: number;
  style: string;
}

const FONTS = [
  {
    name: "IBM Plex Mono",
    font: "IBM+Plex+Mono",
    weight: 400,
    style: "normal",
  },
  { name: "IBM Plex Mono", font: "IBM+Plex+Mono", weight: 700, style: "bold" },
];

/** Google serves woff2 to anything modern, and satori cannot read it. This is
 * the User-Agent that still gets a plain truetype file back. */
const LEGACY_UA =
  "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; de-at) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1";

async function loadGoogleFont(font: string, weight: number) {
  const API = `https://fonts.googleapis.com/css2?family=${font}:wght@${weight}`;

  const css = await (
    await fetch(API, { headers: { "User-Agent": LEGACY_UA } })
  ).text();

  const resource = css.match(
    /src: url\((.+?)\) format\('(opentype|truetype)'\)/
  );

  if (!resource) throw new Error("Failed to download dynamic font");

  const res = await fetch(resource[1]);

  if (!res.ok) {
    throw new Error("Failed to download dynamic font. Status: " + res.status);
  }

  return res.arrayBuffer();
}

let cached: Promise<LoadedFont[]> | undefined;

/**
 * The two weights every satori template draws with, fetched once for the whole
 * build.
 *
 * Google will subset a font down to a `&text=` string, and asking it per image
 * is what this used to do — four requests per rendered image, none of them
 * reusable, because every subset carried something unique to that image. That
 * scales with the number of posts and Hall of Fame members, and a single 429
 * in the middle of it fails the deploy. Two requests for the whole latin face
 * cost 149KB and are constant no matter how much the site grows.
 *
 * It also removes a failure mode rather than just a cost: a hand-built subset
 * can omit a glyph the template actually draws, which satori renders as a
 * blank box without erroring. The full face cannot.
 */
export default function loadGoogleFonts(): Promise<LoadedFont[]> {
  cached ??= Promise.all(
    FONTS.map(async ({ name, font, weight, style }) => ({
      name,
      data: await loadGoogleFont(font, weight),
      weight,
      style,
    }))
  );

  return cached;
}
