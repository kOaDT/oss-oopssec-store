import { z } from "zod";

export const reviewsAuditQuerySchema = z.object({
  author: z.string().optional(),
});

export const analyticsQuerySchema = z.object({
  ip: z.string().optional(),
});
