import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { generateGiftCardCode, isValidDenomination } from "@/lib/gift-card";
import { parseBody } from "@/lib/validation";
import { createGiftCardBodySchema } from "@/lib/validation/schemas/gift-cards";

export const GET = withAuth(async (_request, _context, user) => {
  try {
    const giftCards = await prisma.giftCard.findMany({
      where: { buyerId: user.id },
      select: {
        id: true,
        amount: true,
        recipientEmail: true,
        message: true,
        status: true,
        createdAt: true,
        redeemedAt: true,
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(giftCards);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/gift-cards" },
      "Error fetching gift cards"
    );
    return NextResponse.json(
      { error: "Failed to fetch gift cards" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const parsed = await parseBody(request, createGiftCardBodySchema);
    if (!parsed.success) return parsed.response;
    const { amount, recipientEmail, message } = parsed.data;

    if (!isValidDenomination(amount)) {
      return NextResponse.json(
        { error: "Select a valid denomination ($25, $50, $100, or $500)" },
        { status: 400 }
      );
    }

    const createdAt = new Date();
    const code = generateGiftCardCode(createdAt.getTime());

    const giftCard = await prisma.giftCard.create({
      data: {
        code,
        amount,
        recipientEmail: recipientEmail.trim().toLowerCase(),
        message: message?.trim() || null,
        status: "PENDING",
        buyerId: user.id,
        createdAt,
      },
      select: {
        id: true,
        amount: true,
        recipientEmail: true,
        message: true,
        status: true,
        createdAt: true,
      },
    });

    logger.info(
      {
        route: "/api/gift-cards",
        giftCardId: giftCard.id,
        recipientEmail: giftCard.recipientEmail,
        amount: giftCard.amount,
      },
      `Delivered gift card to ${giftCard.recipientEmail}`
    );

    return NextResponse.json(giftCard, { status: 201 });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/gift-cards" },
      "Error creating gift card"
    );
    return NextResponse.json(
      { error: "Failed to create gift card" },
      { status: 500 }
    );
  }
});
