import { z } from "zod";

export const verifyFlagBodySchema = z.object({
  flag: z.string(),
});
