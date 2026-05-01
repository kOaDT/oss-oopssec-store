import { z } from "zod";

export const applyCouponBodySchema = z.object({
  code: z.string(),
  cartTotal: z.number().positive("Valid cart total is required"),
});
