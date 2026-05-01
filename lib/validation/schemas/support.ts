import { z } from "zod";

export const supportRequestBodySchema = z.object({
  email: z.string(),
  title: z.string(),
  description: z.string(),
  screenshotUrl: z.string().optional(),
});
