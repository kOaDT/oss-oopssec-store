import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { hashMD5, createWeakJWT, setAuthCookie } from "@/lib/server-auth";

const LOGIN_FLAG = "OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, password, redirect } = body;

    console.log("[auth] login attempt", { email, password, flag: LOGIN_FLAG });

    if (!email || !password) {
      return NextResponse.json(
        { error: "Email and password are required" },
        { status: 400 }
      );
    }

    const hashedPassword = hashMD5(password);

    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        password: true,
        role: true,
      },
    });

    if (!user) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 }
      );
    }

    if (user.password !== hashedPassword) {
      return NextResponse.json({ error: "Invalid password" }, { status: 401 });
    }

    const token = createWeakJWT({
      id: user.id,
      email: user.email,
      role: user.role,
      hint: "The secret is not so secret",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    });

    const isVisBruta = user.email === "vis.bruta@example.com";
    let flagData = null;

    if (isVisBruta) {
      const bruteForceFlag = await prisma.flag.findUnique({
        where: { slug: "brute-force-no-rate-limiting" },
      });
      if (bruteForceFlag) {
        flagData = bruteForceFlag.flag;
      }
    }

    const response = NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      flag: flagData,
    });

    setAuthCookie(response, token);

    if (redirect) {
      response.cookies.set("oauth_callback", "1", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60,
        path: "/internal/oauth/callback",
      });
    }

    return response;
  } catch (error) {
    console.error("Error during login:", error);
    return NextResponse.json(
      { error: "Failed to authenticate" },
      { status: 500 }
    );
  }
}
