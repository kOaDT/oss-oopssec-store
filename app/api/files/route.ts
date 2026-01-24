import { NextRequest, NextResponse } from "next/server";
import { readFile, readdir, stat } from "fs/promises";
import { join, extname } from "path";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const file = searchParams.get("file");
    const listDir = searchParams.get("list");
    const dirPath = searchParams.get("path") || "";

    const baseDir = join(process.cwd(), "documents");

    if (listDir === "true") {
      const targetDir = join(baseDir, dirPath);
      const entries = await readdir(targetDir, { withFileTypes: true });

      const items = await Promise.all(
        entries.map(async (entry) => {
          const fullPath = join(targetDir, entry.name);
          const stats = await stat(fullPath);
          return {
            name: entry.name,
            type: entry.isDirectory() ? "directory" : "file",
            size: stats.size,
            modified: stats.mtime.toISOString(),
          };
        })
      );

      return NextResponse.json({
        path: dirPath,
        items,
      });
    }

    if (!file) {
      return NextResponse.json(
        { error: "File parameter is required" },
        { status: 400 }
      );
    }

    const filePath = join(baseDir, file);
    const extension = extname(file).toLowerCase();

    if (extension === ".pdf") {
      const content = await readFile(filePath);
      return new NextResponse(content, {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `inline; filename="${file.split("/").pop()}"`,
        },
      });
    }

    const content = await readFile(filePath, "utf-8");

    return NextResponse.json({
      filename: file,
      content,
    });
  } catch (error) {
    console.error("Error reading file:", error);
    return NextResponse.json({ error: "Failed to read file" }, { status: 500 });
  }
}
