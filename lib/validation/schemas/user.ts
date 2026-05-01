import { z } from "zod";

export const updateProfileBodySchema = z.object({
  displayName: z.string().optional(),
  bio: z.string().optional(),
});

export const exportUserDataBodySchema = z.object({
  format: z.string({ error: "Missing required fields: format and fields" }),
  fields: z
    .array(z.unknown(), { error: "Fields must be a non-empty array" })
    .min(1, "Fields must be a non-empty array"),
});

export const createSupportAccessBodySchema = z
  .object({
    email: z.string().optional(),
  })
  .default({});
