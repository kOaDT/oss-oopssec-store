import { z } from "zod";

export const siemAuthBodySchema = z.object({
  username: z.string(),
  password: z.string(),
});

export const logsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  level: z.string().optional(),
  search: z.string().optional(),
});
