import { z } from "zod";

export const aiAssistantBodySchema = z.object({
  message: z
    .string()
    .max(2000, "Message too long. Maximum 2000 characters allowed."),
  apiKey: z.string(),
  mcpServerUrl: z.string().optional(),
});
