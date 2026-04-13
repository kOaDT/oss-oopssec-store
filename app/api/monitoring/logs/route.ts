import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";

const SIEM_USER = "root";
const SIEM_PASS = "admin";

function isAuthenticated(request: NextRequest): boolean {
  const authHeader = request.headers.get("authorization");
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const [user, pass] = decoded.split(":");
    if (user === SIEM_USER && pass === SIEM_PASS) {
      return true;
    }
  }

  const siemSession = request.cookies.get("siem_session");
  if (siemSession?.value === "authenticated") {
    return true;
  }

  return false;
}

function parseLine(line: string) {
  try {
    return JSON.parse(line);
  } catch {
    return {
      timestamp: new Date().toISOString(),
      level: "log",
      message: line,
    };
  }
}

export async function GET(request: NextRequest) {
  if (!isAuthenticated(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const logFile = path.join(process.cwd(), "logs", "app.log");

  if (!fs.existsSync(logFile)) {
    return NextResponse.json({ logs: [], total: 0, page: 1, totalPages: 0 });
  }

  try {
    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const limit = Math.min(
      200,
      Math.max(1, parseInt(searchParams.get("limit") || "100", 10))
    );
    const level = searchParams.get("level") || "";
    const search = searchParams.get("search") || "";

    const content = fs.readFileSync(logFile, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    let parsed = lines.map(parseLine);

    if (level || search) {
      const searchLower = search.toLowerCase();
      parsed = parsed.filter((entry) => {
        if (level && entry.level !== level) return false;
        if (
          search &&
          !(entry.message ?? "").toLowerCase().includes(searchLower)
        )
          return false;
        return true;
      });
    }

    const total = parsed.length;
    const totalPages = Math.ceil(total / limit);
    const start = total - page * limit;
    const end = total - (page - 1) * limit;
    const logs = parsed.slice(Math.max(0, start), end).reverse();

    return NextResponse.json({ logs, total, page, totalPages });
  } catch {
    return NextResponse.json({ error: "Failed to read logs" }, { status: 500 });
  }
}
