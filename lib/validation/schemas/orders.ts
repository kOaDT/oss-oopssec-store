import { z } from "zod";

export const createOrderBodySchema = z.object({
  total: z.number().positive("Valid total is required"),
  couponCode: z.string().optional(),
});

export const updateOrderStatusBodySchema = z.object({
  status: z.string(),
});

export const orderSearchBodySchema = z.object({
  status: z.string().optional(),
});
