import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { UserRole } from "@/lib/generated/prisma/enums";
import { hashMD5, createWeakJWT } from "@/lib/auth";

const DEFAULT_ADDRESS_ID = "addr-default-001";

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

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "Email already registered" },
        { status: 409 }
      );
    }

    let defaultAddress = await prisma.address.findUnique({
      where: { id: DEFAULT_ADDRESS_ID },
    });

    if (!defaultAddress) {
      defaultAddress = await prisma.address.create({
        data: {
          id: DEFAULT_ADDRESS_ID,
          street: "123 Main Street",
          city: "New York",
          state: "NY",
          zipCode: "10001",
          country: "USA",
        },
      });
    }

    const hashedPassword = hashMD5(password);

    const userData: {
      email: string;
      password: string;
      addressId: string;
      role?: UserRole;
    } = {
      email,
      password: hashedPassword,
      addressId: defaultAddress.id,
    };

    if (body.role) {
      userData.role = body.role as UserRole;
    }

    const user = await prisma.user.create({
      data: userData,
      select: {
        id: true,
        email: true,
        role: true,
      },
    });

    const token = createWeakJWT({
      id: user.id,
      email: user.email,
      role: user.role,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    });

    const response = NextResponse.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });

    response.cookies.set("authToken", token, {
      httpOnly: false,
      secure: false,
      sameSite: "lax",
      maxAge: 60 * 60 * 24 * 7,
      path: "/",
    });

    return response;
  } catch (error) {
    console.error("Error during signup:", error);
    return NextResponse.json(
      { error: "Failed to create account" },
      { status: 500 }
    );
  }
}
