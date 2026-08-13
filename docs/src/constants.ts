import type { Props } from "astro";
import IconMail from "@/assets/icons/IconMail.svg";
import IconGitHub from "@/assets/icons/IconGitHub.svg";
import IconNpm from "@/assets/icons/IconNpm.svg";
import IconDocker from "@/assets/icons/IconDocker.svg";
import IconTryHackMe from "@/assets/icons/IconTryHackMe.svg";
import IconWhatsapp from "@/assets/icons/IconWhatsapp.svg";
import IconFacebook from "@/assets/icons/IconFacebook.svg";
import IconTelegram from "@/assets/icons/IconTelegram.svg";
import IconPinterest from "@/assets/icons/IconPinterest.svg";
import { SITE } from "@/config";

interface Social {
  name: string;
  href: string;
  linkTitle: string;
  icon: (_props: Props) => Element;
}

export const SOCIALS: Social[] = [
  {
    name: "GitHub",
    href: "https://github.com/kOaDT/oss-oopssec-store",
    linkTitle: `${SITE.title} on GitHub`,
    icon: IconGitHub,
  },
  {
    name: "NPM",
    href: "https://www.npmjs.com/package/create-oss-store",
    linkTitle: `${SITE.title} on NPM`,
    icon: IconNpm,
  },
  {
    name: "Docker Hub",
    href: "https://hub.docker.com/r/leogra/oss-oopssec-store",
    linkTitle: `${SITE.title} on Docker Hub`,
    icon: IconDocker,
  },
  {
    name: "TryHackMe",
    href: "https://tryhackme.com/jr/oopssecstorethesummeraudit",
    linkTitle: `${SITE.title} on TryHackMe`,
    icon: IconTryHackMe,
  },
  {
    name: "Mail",
    href: "mailto:koadt@proton.me",
    linkTitle: `Send an email to ${SITE.title}`,
    icon: IconMail,
  },
] as const;

export const SHARE_LINKS: Social[] = [
  {
    name: "WhatsApp",
    href: "https://wa.me/?text=",
    linkTitle: `Share this post via WhatsApp`,
    icon: IconWhatsapp,
  },
  {
    name: "Facebook",
    href: "https://www.facebook.com/sharer.php?u=",
    linkTitle: `Share this post on Facebook`,
    icon: IconFacebook,
  },
  {
    name: "Telegram",
    href: "https://t.me/share/url?url=",
    linkTitle: `Share this post via Telegram`,
    icon: IconTelegram,
  },
  {
    name: "Pinterest",
    href: "https://pinterest.com/pin/create/button/?url=",
    linkTitle: `Share this post on Pinterest`,
    icon: IconPinterest,
  },
  {
    name: "Mail",
    href: "mailto:?subject=See%20this%20post&body=",
    linkTitle: `Share this post via email`,
    icon: IconMail,
  },
] as const;

export const HALL_OF_FAME_URL =
  "https://github.com/kOaDT/oss-oopssec-store/blob/main/hall-of-fame/data.json";

const DISCUSSIONS_URL =
  "https://github.com/kOaDT/oss-oopssec-store/discussions";

/**
 * Discussion categories reachable from a walkthrough, with the title prefix
 * each one expects. The slugs are what GitHub derives from the category names:
 * rename a category on the repo and these links silently fall back to the
 * generic picker. The app carries its own copy as `askAboutChallengeUrl` in
 * `lib/discussions.ts` — narrower, since a challenge page only ever links to
 * "stuck" — because the docs site is a separate package and cannot import from
 * it. Both read challenge titles from `roadmap.ts` so a thread is named the
 * same whichever entry point opened it.
 */
const DISCUSSION_CATEGORIES = {
  stuck: { slug: "stuck-on-a-challenge", prefix: "[Stuck]" },
  solve: { slug: "show-your-solve", prefix: "[Solve]" },
} as const;

/**
 * Deep link to a new discussion, prefilled for one challenge.
 *
 * `challenge` targets the dropdown of the matching form under
 * `.github/DISCUSSION_TEMPLATE/` by field id, and its value has to match an
 * option verbatim — hence the `Title (slug)` shape the generator emits. An
 * unknown field or a non-matching value is ignored by GitHub, so the worst case
 * is the dropdown coming up empty.
 */
export function challengeDiscussionUrl(
  kind: keyof typeof DISCUSSION_CATEGORIES,
  challenge: { title: string; slug: string }
): string {
  const { slug, prefix } = DISCUSSION_CATEGORIES[kind];
  const params = new URLSearchParams({
    category: slug,
    title: `${prefix} ${challenge.title}`,
    challenge: `${challenge.title} (${challenge.slug})`,
  });
  return `${DISCUSSIONS_URL}/new?${params}`;
}
