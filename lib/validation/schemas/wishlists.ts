import { z } from "zod";

export const createWishlistBodySchema = z.object({
  name: z
    .string()
    .refine((v) => v.trim().length > 0, "Wishlist name is required"),
});

export const addWishlistItemBodySchema = z.object({
  productId: z.string(),
});
