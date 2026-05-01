import { z } from "zod";

export const filesQuerySchema = z.object({
  file: z.string().optional(),
  list: z.string().optional(),
  path: z.string().optional(),
});

export const uploadsParamsSchema = z.object({
  path: z.array(z.string()),
});
