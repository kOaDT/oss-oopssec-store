import type { APIRoute } from "astro";
import { badgeStaticPaths, type HallOfFameEntry } from "@/utils/getHallOfFame";
import { generateBadgePill } from "@/utils/generateBadges";

export const getStaticPaths = badgeStaticPaths;

export const GET: APIRoute<HallOfFameEntry> = async ({ props }) => {
  const svg = await generateBadgePill(props);

  return new Response(svg, {
    headers: { "Content-Type": "image/svg+xml; charset=utf-8" },
  });
};
