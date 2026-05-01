import { z } from "zod";

export const trackingBodySchema = z.object({
  path: z.string().optional(),
  sessionId: z.string().nullable().optional(),
});
