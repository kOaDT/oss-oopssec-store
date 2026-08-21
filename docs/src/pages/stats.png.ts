import type { APIRoute } from "astro";
import { generateStatsPng } from "@/utils/generateStatsCard";

export const GET: APIRoute = async () => {
  const buffer = await generateStatsPng();

  return new Response(buffer, {
    headers: { "Content-Type": "image/png" },
  });
};
