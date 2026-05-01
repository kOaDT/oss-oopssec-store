import { NextRequest, NextResponse } from "next/server";
import { readFile, readdir, stat } from "fs/promises";
import { join, extname } from "path";
import { logger } from "@/lib/logger";
import { parseQuery } from "@/lib/validation";
import { filesQuerySchema } from "@/lib/validation/schemas/files";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const parsed = parseQuery(searchParams, filesQuerySchema);
    if (!parsed.success) return parsed.response;
    const file = parsed.data.file ?? null;
    const listDir = parsed.data.list ?? null;
    const dirPath = parsed.data.path ?? "";

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
    logger.error({ err: error, route: "/api/files" }, "Error reading file");
    return NextResponse.json({ error: "Failed to read file" }, { status: 500 });
  }
}
