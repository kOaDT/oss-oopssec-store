import { z } from "zod";

export const shareTokenQuerySchema = z.object({
  token: z
    .string()
    .min(64, "Missing share token")
    .regex(/^[0-9a-f]+$/i, "Missing share token"),
});
