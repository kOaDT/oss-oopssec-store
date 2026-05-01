import { z } from "zod";

export const productSearchQuerySchema = z.object({
  q: z.string().optional(),
});

export const createReviewBodySchema = z.object({
  content: z.string().trim().min(1, "Content is required"),
  author: z.string().optional(),
});
