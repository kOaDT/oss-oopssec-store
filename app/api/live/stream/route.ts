import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import {
  OFFICIAL_VIDEO_ID,
  STREAM_DEFAULTS,
  BFLA_FLAG_SLUG,
} from "@/lib/live-stream";

// YouTube video IDs are exactly 11 chars: [A-Za-z0-9_-]
const VIDEO_ID_PATTERN = /^[A-Za-z0-9_-]{11}$/;

async function getConfig() {
  let config = await prisma.streamConfig.findFirst();
  if (!config) {
    config = await prisma.streamConfig.create({
      data: { ...STREAM_DEFAULTS, isLive: true, hijacked: false },
    });
  }
  return config;
}

/**
 * VULNERABLE: protected by withAuth only. Any authenticated user — not just
 * admins — receives the full stream config, including the RTMP ingest URL and
 * the broadcast stream key. The "Stream Management" panel is hidden in the UI
 * for non-admins, but the API does not enforce that.
 */
export const GET = withAuth(async () => {
  try {
    const config = await getConfig();
    return NextResponse.json(config);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/live/stream" },
      "Error reading stream config"
    );
    return NextResponse.json(
      { error: "Failed to load stream" },
      { status: 500 }
    );
  }
});

/**
 * VULNERABLE: Broken Function Level Authorization.
 *
 * Swapping the featured live video is an admin-only operation, but this handler
 * is mounted with `withAuth` instead of `withAdminAuth`. The only thing that
 * "restricts" it is the React component hiding the button for non-admins —
 * cosmetic gating that any user bypasses by calling the endpoint directly.
 *
 * The secure version uses `withAdminAuth` and validates the video id.
 */
export const POST = withAuth(async (request, _context, user) => {
  try {
    const body = await request.json().catch(() => ({}));
    const liveVideoId = body?.liveVideoId;

    if (
      typeof liveVideoId !== "string" ||
      !VIDEO_ID_PATTERN.test(liveVideoId)
    ) {
      return NextResponse.json(
        { error: "liveVideoId must be a valid YouTube video id" },
        { status: 400 }
      );
    }

    const config = await getConfig();
    const hijacked = user.role !== "ADMIN" && liveVideoId !== OFFICIAL_VIDEO_ID;

    const updated = await prisma.streamConfig.update({
      where: { id: config.id },
      data: { liveVideoId, hijacked },
    });

    // A non-admin who just rewrote the public broadcast has proven the flaw.
    if (hijacked) {
      const flag = await prisma.flag.findUnique({
        where: { slug: BFLA_FLAG_SLUG },
      });

      logger.warn(
        { userId: user.id, role: user.role, liveVideoId },
        "Live stream hijacked by non-admin user"
      );

      return NextResponse.json({
        ok: true,
        message:
          "Broadcast updated. The public /live page now plays your video.",
        config: updated,
        flag: flag?.flag,
      });
    }

    return NextResponse.json({ ok: true, config: updated });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/live/stream" },
      "Error updating stream config"
    );
    return NextResponse.json(
      { error: "Failed to update stream" },
      { status: 500 }
    );
  }
});
