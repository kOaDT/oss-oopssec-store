import type { APIRoute } from "astro";
import { badgeStaticPaths, type HallOfFameEntry } from "@/utils/getHallOfFame";
import { generateBadgeCard } from "@/utils/generateBadges";

export const getStaticPaths = badgeStaticPaths;

export const GET: APIRoute<HallOfFameEntry> = async ({ props }) => {
  const buffer = await generateBadgeCard(props);

  return new Response(buffer, {
    headers: { "Content-Type": "image/png" },
  });
};
