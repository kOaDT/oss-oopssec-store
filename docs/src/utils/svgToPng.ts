import { Resvg } from "@resvg/resvg-js";

/** Rasterises a satori SVG. Shared by the OG images and the Hall of Fame
 * badges so the two cannot drift apart on render options.
 *
 * Typed as the `Uint8Array` a `Buffer` already is, narrowed to `ArrayBuffer`
 * because that is the only form `BodyInit` accepts: a route can then hand the
 * result straight to `Response` without a re-wrap that would copy the image. */
export function svgBufferToPngBuffer(svg: string): Uint8Array<ArrayBuffer> {
  const png = new Resvg(svg).render().asPng();
  return new Uint8Array(
    png.buffer,
    png.byteOffset,
    png.byteLength
  ) as Uint8Array<ArrayBuffer>;
}
