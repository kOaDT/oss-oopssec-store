import satori from "satori";
import loadGoogleFonts from "../loadGoogleFont";
import { FONT_FAMILY, PALETTE, PROJECT_NAME } from "./theme";

/** Wide enough for six figures across a README column, narrow enough that
 * GitHub does not scale it down and soften the type. */
const WIDTH = 880;
const PADDING = 40;
const CONTENT_WIDTH = WIDTH - PADDING * 2;

const TRACK_HEIGHT = 10;
const SPARK_HEIGHT = 64;

/** Left column of the difficulty rows, wide enough for "Medium" at 13px. */
const DIFFICULTY_LABEL = 80;
const DIFFICULTY_COUNT = 40;

/**
 * Avatar box and the gap beside it, tried largest first.
 *
 * The row draws every contributor, so the size has to give rather than the
 * list: at 48px the card holds 39 of them in three rows, and each step down
 * buys roughly another ten before the band would start dominating the card.
 * Past the last step the row simply wraps further — a card that grows is still
 * honest, where a truncated row is not.
 */
const AVATAR_STEPS = [
  { size: 48, gap: 12 },
  { size: 40, gap: 10 },
  { size: 32, gap: 8 },
];
const AVATAR_MAX_ROWS = 3;

/** The strip is fixed at three curriculum figures, so the trailing margin can
 * be dropped by index rather than measured off the array. */
const TILES_LAST = 2;

/** Ordered easy to hard, the way the roadmap orders them. */
const DIFFICULTIES = [
  ["EASY", "Easy"],
  ["MEDIUM", "Medium"],
  ["HARD", "Hard"],
];

const numberFormatter = new Intl.NumberFormat("en-US");

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "long",
  day: "numeric",
  timeZone: "UTC",
});

/**
 * How large the avatars are drawn, given how many there are. Exported because
 * the source images are fetched at twice this size, and that decision has to
 * follow the layout rather than guess at it.
 */
export function avatarLayout(contributors) {
  const fits = AVATAR_STEPS.find(({ size, gap }) => {
    const perRow = Math.floor((CONTENT_WIDTH + gap) / (size + gap));
    return Math.ceil(contributors / perRow) <= AVATAR_MAX_ROWS;
  });

  return fits ?? AVATAR_STEPS[AVATAR_STEPS.length - 1];
}

function box(style, children) {
  return {
    type: "div",
    props: { style: { display: "flex", ...style }, children },
  };
}

function text(content, style) {
  return {
    type: "div",
    props: { style: { display: "flex", ...style }, children: content },
  };
}

/** The uppercase caption every band opens with. */
function caption(content) {
  return text(content, {
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.14em",
    color: PALETTE.muted,
  });
}

function rule(style = {}) {
  return box({ height: 1, background: PALETTE.line, ...style }, []);
}

/**
 * One curriculum figure in the top strip.
 *
 * The tiles are sized by their content and spaced by hand rather than stretched
 * across the width. Three figures spread over 800px read as three things that
 * happen to be far apart; grouped at the left they read as one statement, which
 * is what they are.
 */
function tile({ value, label }, index) {
  return box(
    {
      flexDirection: "column",
      marginRight: index === TILES_LAST ? 0 : 110,
    },
    [
      text(numberFormatter.format(value), { fontSize: 44, fontWeight: 700 }),
      text(label, {
        marginTop: 8,
        fontSize: 11,
        letterSpacing: "0.14em",
        color: PALETTE.muted,
      }),
    ]
  );
}

/**
 * One fact on the line under the strip: the figure, then what it counts.
 *
 * These sit below the curriculum tiles and a size down from them on purpose.
 * Contributors and Hall of Fame entries say how the project is received, which
 * is a different kind of fact from what it contains — drawn at the same weight,
 * as they were, the strip claimed the two were interchangeable.
 */
function socialFact({ value, label, color }) {
  return box({ alignItems: "center" }, [
    text(numberFormatter.format(value), {
      fontSize: 13,
      fontWeight: 700,
      color: color ?? PALETTE.text,
    }),
    text(label, { marginLeft: 7, fontSize: 13, color: PALETTE.muted }),
  ]);
}

function socialLine(facts) {
  const separated = [];
  for (const fact of facts) {
    if (separated.length > 0) {
      separated.push(
        text("·", {
          marginLeft: 12,
          marginRight: 12,
          fontSize: 13,
          color: PALETTE.muted,
        })
      );
    }
    separated.push(socialFact(fact));
  }

  return box({ marginTop: 22, alignItems: "center" }, separated);
}

/**
 * One difficulty per row: name, a track filled to its share of the curriculum,
 * and the count.
 *
 * This was a single stacked bar with a tinted segment per difficulty, which is
 * the compact way to draw a mix and the wrong way to draw this one. Three steps
 * of one hue that each clear 3:1 against `ink` are necessarily close to each
 * other, so telling the segments apart came down to a colour discrimination the
 * card was in no position to make easy. Giving each difficulty its own track
 * removes the discrimination task rather than tuning it: every bar is the full
 * accent, and the reader compares lengths, which is what the data was about.
 */
function difficultyRow([key, label], byDifficulty, total, index) {
  const value = byDifficulty[key];
  const share = total > 0 ? (value / total) * 100 : 0;

  return box({ alignItems: "center", marginTop: index === 0 ? 16 : 12 }, [
    text(label, {
      width: DIFFICULTY_LABEL,
      fontSize: 13,
      color: PALETTE.muted,
    }),
    box(
      {
        flexGrow: 1,
        height: TRACK_HEIGHT,
        borderRadius: TRACK_HEIGHT / 2,
        background: PALETTE.line,
      },
      [
        box(
          {
            width: `${share.toFixed(2)}%`,
            height: "100%",
            borderRadius: TRACK_HEIGHT / 2,
            background: PALETTE.product,
          },
          []
        ),
      ]
    ),
    text(numberFormatter.format(value), {
      width: DIFFICULTY_COUNT,
      justifyContent: "flex-end",
      fontSize: 13,
      fontWeight: 700,
      color: PALETTE.text,
    }),
  ]);
}

/**
 * Weekly commit totals as a bar sparkline. A quiet week still gets a stub the
 * height of the bar's own radius, so the baseline stays readable as a row of
 * weeks rather than a gap in the chart.
 */
function sparkline(commitsByWeek) {
  const peak = Math.max(...commitsByWeek);

  return box(
    { height: SPARK_HEIGHT, marginTop: 14, alignItems: "flex-end" },
    commitsByWeek.map((commits, index) =>
      box(
        {
          flexGrow: 1,
          flexBasis: 0,
          marginRight: index === commitsByWeek.length - 1 ? 0 : 4,
          height: Math.max(3, Math.round((SPARK_HEIGHT * commits) / peak)),
          background: commits > 0 ? PALETTE.product : PALETTE.line,
          borderRadius: 2,
        },
        []
      )
    )
  );
}

/**
 * The circle drawn for a contributor whose avatar could not be had — a GIF,
 * which resvg will not decode, or a CDN that did not answer. It is the same
 * initial-on-a-slate the Hall of Fame card falls back to, in muted rather than
 * gold: on this card the gold belongs to the Hall of Fame figure alone.
 */
function monogram(login, size, frame) {
  return text(login.slice(0, 1).toUpperCase(), {
    ...frame,
    alignItems: "center",
    justifyContent: "center",
    background: PALETTE.label,
    color: PALETTE.muted,
    fontSize: Math.round(size * 0.38),
    fontWeight: 700,
  });
}

/** Every contributor, wrapping onto as many rows as it takes. */
function avatarRow(contributors, { size, gap }) {
  return box(
    { marginTop: 14, flexWrap: "wrap", gap },
    contributors.map(({ login, avatar }) => {
      const frame = {
        width: size,
        height: size,
        borderRadius: size / 2,
        flexShrink: 0,
      };

      return avatar
        ? {
            type: "img",
            props: { src: avatar, width: size, height: size, style: frame },
          }
        : monogram(login, size, frame);
    })
  );
}

/** A caption on the left with a muted figure pushed to the right of the band. */
function bandHeader(label, note) {
  return box({ justifyContent: "space-between", alignItems: "center" }, [
    caption(label),
    text(note, { fontSize: 12, color: PALETTE.muted }),
  ]);
}

/**
 * The README stats card.
 *
 * Everything drawn from the curriculum is local data and always present; the
 * GitHub bands are dropped when the API answered with nothing rather than
 * rendered as zeroes, because a card claiming zero commits during a rate limit
 * is worse than a card that does not mention them. The height is left to satori
 * for the same reason: a dropped band closes up instead of leaving a hole.
 */
export default async function statsCard({
  totalChallenges,
  chapters,
  walkthroughs,
  byDifficulty,
  hallOfFame,
  repoUrl,
  stats,
  contributors,
}) {
  const tiles = [
    { value: totalChallenges, label: "CHALLENGES" },
    { value: chapters, label: "CHAPTERS" },
    { value: walkthroughs, label: "WALKTHROUGHS" },
  ];

  const social = [
    ...(contributors.length > 0
      ? [
          {
            value: contributors.length,
            label: contributors.length === 1 ? "contributor" : "contributors",
          },
        ]
      : []),
    {
      value: hallOfFame,
      /* "players" is the project's own word for them, in the app's
       * `player-dashboard` and in the README's comparison table alike. */
      label: `${hallOfFame === 1 ? "player" : "players"} in the Hall of Fame`,
      color: PALETTE.accent,
    },
  ];

  const commits = stats.commitsByWeek;
  const commitTotal = commits.reduce((sum, week) => sum + week, 0);

  return satori(
    box(
      {
        width: WIDTH,
        flexDirection: "column",
        padding: PADDING,
        background: PALETTE.ink,
        fontFamily: FONT_FAMILY,
        color: PALETTE.text,
      },
      [
        box({ justifyContent: "space-between", alignItems: "center" }, [
          box({ alignItems: "center" }, [
            box(
              {
                width: 12,
                height: 12,
                borderRadius: 3,
                background: PALETTE.product,
                marginRight: 14,
              },
              []
            ),
            text(PROJECT_NAME, { fontSize: 26, fontWeight: 700 }),
          ]),
          text(repoUrl, { fontSize: 12, color: PALETTE.muted }),
        ]),

        rule({ marginTop: 24, marginBottom: 28 }),

        box({}, tiles.map(tile)),
        socialLine(social),

        box({ flexDirection: "column", marginTop: 32 }, [
          caption("DIFFICULTY MIX"),
          ...DIFFICULTIES.map((difficulty, index) =>
            difficultyRow(difficulty, byDifficulty, totalChallenges, index)
          ),
        ]),

        ...(commitTotal > 0
          ? [
              box({ flexDirection: "column", marginTop: 32 }, [
                bandHeader(
                  `COMMITS · LAST ${commits.length} WEEKS`,
                  `${numberFormatter.format(commitTotal)} commits`
                ),
                sparkline(commits),
              ]),
            ]
          : []),

        ...(contributors.length > 0
          ? [
              box({ flexDirection: "column", marginTop: 32 }, [
                caption("CONTRIBUTORS"),
                avatarRow(contributors, avatarLayout(contributors.length)),
              ]),
            ]
          : []),

        rule({ marginTop: 32, marginBottom: 20 }),

        box({ justifyContent: "space-between" }, [
          text(
            `Updated ${dateFormatter.format(new Date())} · refreshed daily`,
            {
              fontSize: 11,
              color: PALETTE.muted,
            }
          ),
          text("MIT", { fontSize: 11, color: PALETTE.muted }),
        ]),
      ]
    ),
    {
      width: WIDTH,
      embedFont: true,
      fonts: await loadGoogleFonts(),
    }
  );
}
