/**
 * Both badges carry their own opaque background, so they hold up on a light or
 * a dark README alike — GitHub proxies them through camo, which rules out
 * reacting to the reader's colour scheme.
 */
export const PALETTE = {
  ink: "#020617",
  label: "#0f172a",
  /** Gold, and the only award colour. Anything set on it takes `ink`, not
   * white: white on gold sits at 1.7:1, well under AA. */
  accent: "#fbbf24",
  /** The emerald of the docs dark accent, cousin of the app's `primary-500`.
   * Reserved for the chapter bullets, which is what ties the card back to the
   * product without competing with the gold. */
  chapter: "#10b981",
  text: "#ffffff",
  muted: "#94a3b8",
  line: "#1e293b",
};

export const FONT_FAMILY = "IBM Plex Mono";

export const PROJECT_NAME = "OopsSec Store";

/** The pill is measured against the shields.io badges beside it in a README,
 * where every character counts; the card has room for the full name. */
export const PROJECT_SHORT = "OopsSec";

export const HALL_OF_FAME = "Hall of Fame";

/**
 * Deliberately free of any flag count. Badges are re-rendered on every docs
 * deploy, so a total baked in today would start overstating what its holder
 * actually played the day a new challenge lands. The card pairs this claim
 * with the date the entry was merged, which is what keeps it true as the
 * curriculum grows underneath it.
 *
 * Written in the project's own `OSS{...}` flag format: the card carries no
 * emblem, so this is the one element that says "capture the flag" to a reader
 * who has never heard of the project. It is not a flag any challenge accepts.
 */
export const COMPLETION_CLAIM = "OSS{c4ptur3d_3v3ry_fl4g}";

export const CURRICULUM_LABEL = "Curriculum covered";
