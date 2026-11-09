import { z } from "zod";

export const revokeCredentialsSchema = z.object({
  credentials: z.array(z.string().min(1).max(200)).min(1).max(1000),
});
