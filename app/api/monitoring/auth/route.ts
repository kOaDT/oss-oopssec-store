import { NextResponse } from "next/server";
import { parseBody } from "@/lib/validation";
import { siemAuthBodySchema } from "@/lib/validation/schemas/monitoring";

const SIEM_USER = "root";
const SIEM_PASS = "admin";

export async function POST(request: Request) {
  try {
    const parsed = await parseBody(request, siemAuthBodySchema);
    if (!parsed.success) return parsed.response;
    const { username, password } = parsed.data;

    if (username === SIEM_USER && password === SIEM_PASS) {
      const response = NextResponse.json({ success: true });
      response.cookies.set("siem_session", "authenticated", {
        httpOnly: true,
        path: "/",
        maxAge: 60 * 60 * 24,
      });
      return response;
    }

    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
