import path from "path";

export const getDatabaseUrl = (): string => {
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
