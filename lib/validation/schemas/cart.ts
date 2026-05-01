import { z } from "zod";

export const addCartItemBodySchema = z.object({
  productId: z.string(),
  quantity: z.number().int().min(1, "Valid quantity is required"),
});

export const updateCartItemBodySchema = z.object({
  quantity: z.number().int().min(1, "Valid quantity is required"),
});
