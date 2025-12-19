import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const count = await prisma.flag.count();
    return NextResponse.json({ count });
  } catch (error) {
    console.error("Error fetching flag count:", error);
    return NextResponse.json(
      { error: "Failed to fetch flag count" },
      { status: 500 }
    );
  }
}
