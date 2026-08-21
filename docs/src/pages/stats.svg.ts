import type { APIRoute } from "astro";
import { generateStatsSvg } from "@/utils/generateStatsCard";

export const GET: APIRoute = async () => {
  const svg = await generateStatsSvg();

  return new Response(svg, {
    headers: { "Content-Type": "image/svg+xml; charset=utf-8" },
  });
};
