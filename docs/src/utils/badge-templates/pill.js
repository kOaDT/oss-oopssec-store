import satori from "satori";
import loadGoogleFonts from "../loadGoogleFont";
import { FONT_FAMILY, HALL_OF_FAME, PALETTE, PROJECT_SHORT } from "./theme";

const HEIGHT = 24;
const FONT_SIZE = 12;

/** shields.io's `flat` style, which is what this badge sits next to in a
 * README. Squared-off corners are the tell that a badge was not made by
 * shields, so the outer segments carry the radius and the seam stays sharp. */
const RADIUS = 3;

function segment(text, background, color, weight, radius) {
  return {
    type: "div",
    props: {
      style: {
        display: "flex",
        alignItems: "center",
        height: "100%",
        padding: "0 10px",
        background,
        color,
        fontSize: FONT_SIZE,
        fontWeight: weight,
        letterSpacing: "0.02em",
        ...radius,
      },
      children: text,
    },
  };
}

/**
 * The inline badge, sized like a shields.io pill so it sits level with the ones
 * already in a README. Only the height is fixed: satori derives the width from
 * the text, which is what lets a 3-character username and a 39-character one
 * both come out tight.
 */
export default async function pillBadge(entry) {
  const value = `${HALL_OF_FAME} · ${entry.username}`;

  return satori(
    {
      type: "div",
      props: {
        style: {
          display: "flex",
          height: "100%",
          fontFamily: FONT_FAMILY,
        },
        children: [
          segment(PROJECT_SHORT, PALETTE.label, PALETTE.text, 400, {
            borderTopLeftRadius: RADIUS,
            borderBottomLeftRadius: RADIUS,
          }),
          segment(value, PALETTE.accent, PALETTE.ink, 700, {
            borderTopRightRadius: RADIUS,
            borderBottomRightRadius: RADIUS,
          }),
        ],
      },
    },
    {
      height: HEIGHT,
      embedFont: true,
      fonts: await loadGoogleFonts(PROJECT_SHORT + value),
    }
  );
}
