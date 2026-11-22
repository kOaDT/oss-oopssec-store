import { z } from "zod";
import {
  MAX_CART_ITEM_QUANTITY,
  MAX_CART_ITEM_QUANTITY_MESSAGE,
} from "@/lib/cart";

const quantitySchema = z
  .number()
  .int()
  .min(1, "Valid quantity is required")
  .max(MAX_CART_ITEM_QUANTITY, MAX_CART_ITEM_QUANTITY_MESSAGE);

export const addCartItemBodySchema = z.object({
  productId: z.string(),
  quantity: quantitySchema,
});

export const updateCartItemBodySchema = z.object({
  quantity: quantitySchema,
});
