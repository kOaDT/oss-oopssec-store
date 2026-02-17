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

export async function GET(request: NextRequest) {
  if (!isAuthenticated(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const logFile = path.join(process.cwd(), "logs", "app.log");

  if (!fs.existsSync(logFile)) {
    return NextResponse.json({ logs: [] });
  }

  try {
    const content = fs.readFileSync(logFile, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    const logs = lines.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return {
          timestamp: new Date().toISOString(),
          level: "log",
          message: line,
        };
      }
    });

    return NextResponse.json({ logs });
  } catch {
    return NextResponse.json({ error: "Failed to read logs" }, { status: 500 });
  }
}
