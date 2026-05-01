import { z } from "zod";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const createGiftCardBodySchema = z.object({
  amount: z.number(),
  recipientEmail: z
    .string()
    .regex(EMAIL_REGEX, "A valid recipient email is required"),
  message: z
    .string()
    .max(500, "Message must be 500 characters or fewer")
    .optional(),
});

export const redeemGiftCardBodySchema = z.object({
  code: z.string(),
});
