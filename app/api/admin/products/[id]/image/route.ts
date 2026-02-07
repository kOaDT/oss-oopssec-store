import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";
import { writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { existsSync } from "fs";

const ALLOWED_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/svg+xml",
];

const MAX_FILE_SIZE = 5 * 1024 * 1024;

function containsMaliciousContent(content: string): boolean {
  const lowerContent = content.toLowerCase();
  return (
    lowerContent.includes("<script") ||
    lowerContent.includes("onload=") ||
    lowerContent.includes("onerror=") ||
    lowerContent.includes("onclick=") ||
    lowerContent.includes("onmouseover=") ||
    lowerContent.includes("javascript:")
  );
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (user.role !== "ADMIN") {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const { id } = await params;

    const product = await prisma.product.findUnique({
      where: { id },
    });

    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    const formData = await request.formData();
    const file = formData.get("image") as File | null;

    if (!file) {
      return NextResponse.json(
        { error: "No image file provided" },
        { status: 400 }
      );
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: "File size exceeds 5MB limit" },
        { status: 400 }
      );
    }

    if (!ALLOWED_CONTENT_TYPES.includes(file.type)) {
      return NextResponse.json(
        {
          error: "Invalid file type. Allowed types: JPEG, PNG, GIF, WebP, SVG",
        },
        { status: 400 }
      );
    }

    const uploadsDir = join(process.cwd(), "uploads");
    if (!existsSync(uploadsDir)) {
      await mkdir(uploadsDir, { recursive: true });
    }

    const timestamp = Date.now();
    const originalName = file.name.replace(/[^a-zA-Z0-9.-]/g, "_");
    const filename = `${id}-${timestamp}-${originalName}`;

    const buffer = Buffer.from(await file.arrayBuffer());
    const filepath = join(uploadsDir, filename);
    await writeFile(filepath, buffer);

    const imageUrl = `/api/uploads/${filename}`;

    await prisma.product.update({
      where: { id },
      data: { imageUrl },
    });

    const isSvg = file.type === "image/svg+xml" || file.name.endsWith(".svg");
    if (isSvg) {
      const content = buffer.toString("utf-8");
      if (containsMaliciousContent(content)) {
        const flag = await prisma.flag.findUnique({
          where: { slug: "malicious-file-upload" },
        });

        return NextResponse.json({
          message: "Image uploaded successfully",
          imageUrl,
          productName: product.name,
          flag: flag?.flag,
        });
      }
    }

    return NextResponse.json({
      message: "Image uploaded successfully",
      imageUrl,
      productName: product.name,
    });
  } catch (error) {
    console.error("Error uploading image:", error);
    return NextResponse.json(
      { error: "Failed to upload image" },
      { status: 500 }
    );
  }
}
