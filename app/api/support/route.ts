import { NextRequest, NextResponse } from "next/server";
import { logger } from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    const { email, title, description, screenshotUrl } = await request.json();

    if (!email || !title || !description) {
      return NextResponse.json(
        { error: "Email, title, and description are required" },
        { status: 400 }
      );
    }

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
          { error: fetchError, route: "/api/support" },
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
      { error: error, route: "/api/support" },
      "Error processing support request"
    );
    return NextResponse.json(
      { error: "Failed to process support request" },
      { status: 500 }
    );
  }
}
