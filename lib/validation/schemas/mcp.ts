import { z } from "zod";

export const jsonRpcRequestSchema = z.object({
  jsonrpc: z.string(),
  method: z.string(),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  params: z.record(z.string(), z.unknown()).optional(),
});
