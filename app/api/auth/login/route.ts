import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { hashMD5, createWeakJWT } from "@/lib/server-auth";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, password } = body;

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

    return NextResponse.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      flag: flagData,
    });
  } catch (error) {
    console.error("Error during login:", error);
    return NextResponse.json(
      { error: "Failed to authenticate" },
      { status: 500 }
    );
  }
}
