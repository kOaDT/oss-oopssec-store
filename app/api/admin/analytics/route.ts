import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";

export async function GET(request: NextRequest) {
  const user = await getAuthenticatedUser(request);

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (user.role !== "ADMIN") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const { searchParams } = new URL(request.url);
    const filterIp = searchParams.get("ip");

    const totalVisits = await prisma.visitorLog.count();
    const uniqueIps = await prisma.visitorLog.groupBy({
      by: ["ip"],
    });

    let filteredVisits: unknown[] = [];

    if (filterIp) {
      // Safe query using Prisma's parameterized queries
      filteredVisits = await prisma.visitorLog.findMany({
        where: {
          ip: {
            contains: filterIp,
          },
        },
        orderBy: { createdAt: "desc" },
        take: 100,
      });
    } else {
      filteredVisits = await prisma.visitorLog.findMany({
        orderBy: { createdAt: "desc" },
        take: 100,
      });
    }

    const topIps = await prisma.visitorLog.groupBy({
      by: ["ip"],
      _count: { ip: true },
      orderBy: { _count: { ip: "desc" } },
      take: 10,
    });

    return NextResponse.json({
      stats: {
        totalVisits,
        uniqueVisitors: uniqueIps.length,
      },
      topIps: topIps.map((item) => ({
        ip: item.ip,
        count: item._count.ip,
      })),
      visits: filteredVisits,
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    return NextResponse.json(
      { error: "Failed to fetch analytics" },
      { status: 500 }
    );
  }
}
