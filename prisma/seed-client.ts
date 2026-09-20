import { config } from "dotenv";
import { PrismaClient } from "../lib/generated/prisma/client";
import { getDatabaseUrl } from "../lib/database";

config();

export const prisma = new PrismaClient({
  datasources: {
    db: {
      url: getDatabaseUrl(),
    },
  },
});
