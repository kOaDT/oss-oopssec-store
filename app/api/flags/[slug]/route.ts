import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  try {
    const { slug } = await params;
    const flag = await prisma.flag.findUnique({
      where: { slug },
    });

    if (!flag) {
      return NextResponse.json({ error: "Flag not found" }, { status: 404 });
    }

    return NextResponse.json(flag);
  } catch (error) {
    console.error("Error fetching flag:", error);
    return NextResponse.json(
      { error: "Failed to fetch flag" },
      { status: 500 }
    );
  }
}
