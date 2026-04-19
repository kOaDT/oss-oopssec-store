import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

const SEEDED_GIFT_CARD_ID = "gc-seeded-001";
const INSECURE_RANDOMNESS_FLAG = "OSS{1ns3cur3_r4nd0mn3ss_g1ft_c4rd}";
const INVALID_CODE_MESSAGE = "Invalid or already redeemed gift card code";
const SELF_REDEEM_MESSAGE = "You cannot redeem a gift card you sent yourself";

function timingSafeEqualStrings(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < length; i++) {
    const ac = i < a.length ? a.charCodeAt(i) : 0;
    const bc = i < b.length ? b.charCodeAt(i) : 0;
    diff |= ac ^ bc;
  }
  return diff === 0;
}

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const body = await request.json();
    const rawCode = body?.code;

    if (!rawCode || typeof rawCode !== "string") {
      return NextResponse.json(
        { error: INVALID_CODE_MESSAGE },
        { status: 400 }
      );
    }

    const normalized = rawCode.trim().toUpperCase();

    const candidates = await prisma.giftCard.findMany({
      where: { status: "PENDING" },
      select: { id: true, code: true, amount: true, buyerId: true },
    });

    const match = candidates.find((c) =>
      timingSafeEqualStrings(c.code, normalized)
    );

    if (!match) {
      return NextResponse.json(
        { error: INVALID_CODE_MESSAGE },
        { status: 400 }
      );
    }

    if (match.buyerId === user.id) {
      return NextResponse.json({ error: SELF_REDEEM_MESSAGE }, { status: 403 });
    }

    const redeemed = await prisma.giftCard.updateMany({
      where: { id: match.id, status: "PENDING" },
      data: {
        status: "REDEEMED",
        redeemedAt: new Date(),
        redeemedById: user.id,
      },
    });

    if (redeemed.count === 0) {
      return NextResponse.json(
        { error: INVALID_CODE_MESSAGE },
        { status: 400 }
      );
    }

    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: { creditBalance: { increment: match.amount } },
      select: { creditBalance: true },
    });

    const response: {
      success: true;
      amount: number;
      balance: number;
      flag?: string;
    } = {
      success: true,
      amount: match.amount,
      balance: updatedUser.creditBalance,
    };

    if (match.id === SEEDED_GIFT_CARD_ID) {
      response.flag = INSECURE_RANDOMNESS_FLAG;
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/gift-cards/redeem" },
      "Error redeeming gift card"
    );
    return NextResponse.json(
      { error: "Failed to redeem gift card" },
      { status: 500 }
    );
  }
});
