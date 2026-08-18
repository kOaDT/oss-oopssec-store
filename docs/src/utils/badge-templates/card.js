import satori from "satori";
import { SITE } from "@/config";
import { CURRICULUM } from "@/data/roadmap";
import loadGoogleFonts from "../loadGoogleFont";
import {
  COMPLETION_CLAIM,
  CURRICULUM_LABEL,
  FONT_FAMILY,
  HALL_OF_FAME,
  PALETTE,
  PROJECT_NAME,
} from "./theme";

const WIDTH = 1200;
const HEIGHT = 630;
const PADDING = 60;
const AVATAR_SIZE = 120;
const AVATAR_GAP = 32;
const COLUMNS = 3;

/** The size the name is set at when it has the room for it. */
const NAME_FONT_SIZE = 52;

/** Every glyph of a monospaced face advances the same fraction of the font
 * size, so the width a username will take is known before satori lays it out.
 * The figure is IBM Plex Mono's own advance, read off its `unitsPerEm`. */
const MONO_ADVANCE = 0.6;

/** What is left of the row once the avatar and the gap beside it are paid for. */
const NAME_WIDTH = WIDTH - PADDING * 2 - AVATAR_SIZE - AVATAR_GAP;

/**
 * `USERNAME_PATTERN` in `getHallOfFame.ts` accepts up to 39 characters, which
 * is far more than fits at the full size — and satori has no `text-overflow`,
 * so an oversized name silently runs off the card and squeezes the avatar to a
 * sliver on the way out. Shrinking the name is the one degradation that keeps
 * the whole username readable, so it takes the hit rather than the avatar.
 */
function nameFontSize(username) {
  const fits = Math.floor(NAME_WIDTH / (username.length * MONO_ADVANCE));
  return Math.min(NAME_FONT_SIZE, fits);
}

function avatarNode(avatar, username) {
  const frame = {
    width: AVATAR_SIZE,
    height: AVATAR_SIZE,
    borderRadius: "50%",
    border: `4px solid ${PALETTE.accent}`,
    flexShrink: 0,
  };

  if (avatar) {
    return { type: "img", props: { src: avatar, style: frame } };
  }

  return {
    type: "div",
    props: {
      style: {
        ...frame,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: PALETTE.label,
        color: PALETTE.accent,
        fontSize: 56,
        fontWeight: 700,
      },
      children: username.slice(0, 1).toUpperCase(),
    },
  };
}

function stack(children, alignItems) {
  return {
    type: "div",
    props: {
      style: { display: "flex", flexDirection: "column", gap: 6, alignItems },
      children,
    },
  };
}

function line(text, fontSize, color, fontWeight) {
  return {
    type: "div",
    props: {
      style: { display: "flex", fontSize, color, fontWeight },
      children: text,
    },
  };
}

function chapterCell(title) {
  return {
    type: "div",
    props: {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 10,
        width: `${100 / COLUMNS}%`,
        flexShrink: 0,
      },
      children: [
        {
          type: "div",
          props: {
            style: {
              width: 8,
              height: 8,
              borderRadius: 2,
              background: PALETTE.chapter,
              flexShrink: 0,
            },
          },
        },
        line(title, 18, PALETTE.muted, 400),
      ],
    },
  };
}

/**
 * satori implements flexbox only — no CSS grid — so the columns are laid out by
 * slicing the chapter list into rows by hand.
 */
function chapterRows(titles) {
  const rows = [];
  for (let start = 0; start < titles.length; start += COLUMNS) {
    rows.push({
      type: "div",
      props: {
        style: { display: "flex", width: "100%" },
        children: titles.slice(start, start + COLUMNS).map(chapterCell),
      },
    });
  }
  return rows;
}

/**
 * The social card: the one a player posts rather than embeds. It renders the
 * curriculum as it stands at build time, which is why the claim carries the
 * date the entry was merged — that date, not the chapter list, is what pins
 * the achievement down as chapters keep being added.
 */
export default async function cardBadge(entry, { avatar, formattedDate }) {
  const site = new URL(SITE.website);
  const host = site.host + site.pathname;
  const eyebrow = HALL_OF_FAME.toUpperCase();
  const claim = COMPLETION_CLAIM;
  const chapters = CURRICULUM.map(chapter => chapter.title);

  return satori(
    {
      type: "div",
      props: {
        style: {
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          width: "100%",
          height: "100%",
          padding: PADDING,
          background: PALETTE.ink,
          backgroundImage:
            "radial-gradient(circle at 88% 8%, rgba(251, 191, 36, 0.20), transparent 55%)",
          fontFamily: FONT_FAMILY,
        },
        children: [
          {
            type: "div",
            props: {
              style: { display: "flex", flexDirection: "column", gap: 26 },
              children: [
                {
                  type: "div",
                  props: {
                    style: {
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      width: "100%",
                    },
                    children: [
                      line(PROJECT_NAME, 28, PALETTE.text, 700),
                      line(eyebrow, 26, PALETTE.accent, 700),
                    ],
                  },
                },
                {
                  type: "div",
                  props: {
                    style: {
                      display: "flex",
                      alignItems: "center",
                      gap: AVATAR_GAP,
                    },
                    children: [
                      avatarNode(avatar, entry.username),
                      stack(
                        [
                          line(
                            entry.username,
                            nameFontSize(entry.username),
                            PALETTE.text,
                            700
                          ),
                          line(claim, 30, PALETTE.accent, 700),
                          line(formattedDate, 22, PALETTE.muted, 400),
                        ],
                        "flex-start"
                      ),
                    ],
                  },
                },
              ],
            },
          },
          {
            type: "div",
            props: {
              style: {
                display: "flex",
                flexDirection: "column",
                gap: 14,
                borderTop: `2px solid ${PALETTE.line}`,
                paddingTop: 20,
              },
              children: [
                line(CURRICULUM_LABEL, 20, PALETTE.text, 700),
                {
                  type: "div",
                  props: {
                    style: {
                      display: "flex",
                      flexDirection: "column",
                      gap: 12,
                    },
                    children: chapterRows(chapters),
                  },
                },
              ],
            },
          },
          {
            type: "div",
            props: {
              style: {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-end",
                borderTop: `2px solid ${PALETTE.line}`,
                paddingTop: 20,
              },
              children: [
                line(host, 22, PALETTE.muted, 400),
                line(entry.country ?? "", 22, PALETTE.muted, 400),
              ],
            },
          },
        ],
      },
    },
    {
      width: WIDTH,
      height: HEIGHT,
      embedFont: true,
      fonts: await loadGoogleFonts(),
    }
  );
}
