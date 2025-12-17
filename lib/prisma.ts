import { PrismaClient } from "./generated/prisma/client";
import path from "path";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

const getDatabaseUrl = () => {
  const projectRoot = path.resolve(process.cwd());
  const defaultPath = path.resolve(projectRoot, "prisma", "dev.db");

  if (process.env.DATABASE_URL) {
    const dbUrl = process.env.DATABASE_URL.trim().replace(/^"|"$/g, "");

    if (dbUrl.startsWith("file:./")) {
      const relativePath = dbUrl.replace("file:./", "");
      const absolutePath = path.resolve(projectRoot, relativePath);
      return `file:${absolutePath}`;
    }

    if (dbUrl.startsWith("file:")) {
      return dbUrl;
    }
  }

  return `file:${defaultPath}`;
};

const databaseUrl = getDatabaseUrl();

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
  });

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
