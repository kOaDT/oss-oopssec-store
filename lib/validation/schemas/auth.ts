import { z } from "zod";

export const signupBodySchema = z
  .object({
    email: z.string(),
    password: z.string(),
    role: z.string().optional(),
  })
  .passthrough();

export const loginBodySchema = z.object({
  email: z.string(),
  password: z.string(),
  redirect: z.unknown().optional(),
});

export const forgotPasswordBodySchema = z.object({
  email: z.string(),
});

export const resetPasswordBodySchema = z.object({
  token: z.string(),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const supportLoginQuerySchema = z.object({
  token: z.string(),
});
