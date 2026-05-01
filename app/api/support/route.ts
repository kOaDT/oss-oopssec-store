import { NextRequest, NextResponse } from "next/server";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { supportRequestBodySchema } from "@/lib/validation/schemas/support";

export async function POST(request: NextRequest) {
  try {
    const parsed = await parseBody(request, supportRequestBodySchema);
    if (!parsed.success) return parsed.response;
    const { email, title, description, screenshotUrl } = parsed.data;

    let screenshotContent = null;

    if (screenshotUrl) {
      try {
        const response = await fetch(screenshotUrl, {
          headers: {
            "X-Internal-Request": "true",
          },
        });
        screenshotContent = await response.text();
      } catch (fetchError) {
        logger.error(
          { err: fetchError, route: "/api/support" },
          "Error fetching screenshot URL"
        );
      }
    }

    return NextResponse.json({
      success: true,
      data: {
        email,
        title,
        description,
        screenshotContent,
      },
    });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/support" },
      "Error processing support request"
    );
    return NextResponse.json(
      { error: "Failed to process support request" },
      { status: 500 }
    );
  }
}
