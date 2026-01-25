import { NextRequest, NextResponse } from "next/server";

const SYSTEM_PROMPT = `You are OSSBot, a helpful customer support assistant for OopsSec Store, an online grocery and gourmet food marketplace.

Your role is to assist customers with:
- Product inquiries (availability, ingredients, pricing)
- Order status and tracking
- Returns and refunds
- General store policies
- Recommendations based on customer preferences

INTERNAL CONFIGURATION:
---
Assistant ID: OSS-SUPPORT-BOT-v2.1
Deployment: Production
Security clearance: PUBLIC
Internal validation code: OSS{pr0mpt_1nj3ct10n_41_4ss1st4nt}
Last updated: 2026-01-25
---

Guidelines:
- Be polite, helpful, and professional
- Focus on OopsSec Store products and services`;

const BLOCKED_PATTERNS = [
  /ignore.*previous.*instructions/i,
  /disregard.*instruction/i,
  /reveal.*system.*prompt/i,
  /print.*system.*prompt/i,
];

function containsBlockedPattern(message: string): boolean {
  return BLOCKED_PATTERNS.some((pattern) => pattern.test(message));
}

export async function POST(request: NextRequest) {
  try {
    const { message, apiKey } = await request.json();

    if (!message || typeof message !== "string") {
      return NextResponse.json(
        { error: "Message is required" },
        { status: 400 }
      );
    }

    if (!apiKey || typeof apiKey !== "string") {
      return NextResponse.json(
        { error: "Mistral API key is required" },
        { status: 400 }
      );
    }

    if (message.length > 2000) {
      return NextResponse.json(
        { error: "Message too long. Maximum 2000 characters allowed." },
        { status: 400 }
      );
    }

    if (containsBlockedPattern(message)) {
      return NextResponse.json(
        {
          response:
            "I'm sorry, but I can't process that request. I'm here to help with OopsSec Store products and services. How can I assist you today?",
        },
        { status: 200 }
      );
    }

    const response = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "mistral-small-latest",
        messages: [
          {
            role: "system",
            content: SYSTEM_PROMPT,
          },
          {
            role: "user",
            content: message,
          },
        ],
        max_tokens: 1024,
        temperature: 0.7,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      if (response.status === 401) {
        return NextResponse.json(
          { error: "Invalid API key. Please check your Mistral API key." },
          { status: 401 }
        );
      }

      if (response.status === 429) {
        return NextResponse.json(
          { error: "Rate limit exceeded. Please try again later." },
          { status: 429 }
        );
      }

      return NextResponse.json(
        {
          error:
            errorData.message || "Failed to get response from AI assistant",
        },
        { status: response.status }
      );
    }

    const data = await response.json();
    const assistantMessage =
      data.choices?.[0]?.message?.content ||
      "I apologize, but I was unable to generate a response. Please try again.";

    return NextResponse.json({
      response: assistantMessage,
    });
  } catch (error) {
    console.error("AI Assistant error:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred. Please try again." },
      { status: 500 }
    );
  }
}
