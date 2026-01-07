import { NextRequest, NextResponse } from "next/server";

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
        console.error("Error fetching screenshot URL:", fetchError);
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
    console.error("Error processing support request:", error);
    return NextResponse.json(
      { error: "Failed to process support request" },
      { status: 500 }
    );
  }
}
