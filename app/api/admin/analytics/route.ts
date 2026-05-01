import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAdminAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseQuery } from "@/lib/validation";
import { analyticsQuerySchema } from "@/lib/validation/schemas/admin";

export const GET = withAdminAuth(
  async (request: NextRequest, _context, _user) => {
    try {
      const { searchParams } = new URL(request.url);
      const parsed = parseQuery(searchParams, analyticsQuerySchema);
      if (!parsed.success) return parsed.response;
      const filterIp = parsed.data.ip ?? null;

      const totalVisits = await prisma.visitorLog.count();
      const uniqueIps = await prisma.visitorLog.groupBy({
        by: ["ip"],
      });

      let filteredVisits: unknown[] = [];

      if (filterIp) {
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
      logger.error(
        { err: error, route: "/api/admin/analytics" },
        "Error fetching analytics"
      );
      return NextResponse.json(
        { error: "Failed to fetch analytics" },
        { status: 500 }
      );
    }
  }
);
