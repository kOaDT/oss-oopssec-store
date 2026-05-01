import { NextResponse } from "next/server";
import { z, ZodError, type ZodType } from "zod";

type ValidationSuccess<T> = { success: true; data: T };
type ValidationFailure = { success: false; response: NextResponse };
export type ValidationResult<T> = ValidationSuccess<T> | ValidationFailure;

const formatIssues = (error: ZodError) =>
  error.issues.map((issue) => ({
    path: issue.path.join("."),
    message: issue.message,
    code: issue.code,
  }));

export const validationErrorPayload = (error: ZodError) => {
  const details = formatIssues(error);
  return {
    error: details[0]?.message ?? "Validation failed",
    details,
  };
};

const validationErrorResponse = (error: ZodError) =>
  NextResponse.json(validationErrorPayload(error), { status: 400 });

const failure = (response: NextResponse): ValidationFailure => ({
  success: false,
  response,
});

export type ParseBodyOptions = { allowEmptyBody?: boolean };

export async function parseBody<T>(
  request: Request,
  schema: ZodType<T>,
  options: ParseBodyOptions = {}
): Promise<ValidationResult<T>> {
  let raw: unknown;
  try {
    const text = await request.text();
    if (!text) {
      if (!options.allowEmptyBody) {
        return failure(
          NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
        );
      }
      raw = {};
    } else {
      raw = JSON.parse(text);
    }
  } catch {
    return failure(
      NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
    );
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    return failure(validationErrorResponse(result.error));
  }
  return { success: true, data: result.data };
}

export async function parseFormData<T>(
  request: Request,
  schema: ZodType<T>
): Promise<ValidationResult<T>> {
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return failure(
      NextResponse.json({ error: "Invalid form data" }, { status: 400 })
    );
  }

  const raw: Record<string, FormDataEntryValue | FormDataEntryValue[]> = {};
  for (const key of new Set(formData.keys())) {
    const all = formData.getAll(key);
    raw[key] = all.length > 1 ? all : all[0];
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    return failure(validationErrorResponse(result.error));
  }
  return { success: true, data: result.data };
}

export function parseQuery<T>(
  searchParams: URLSearchParams,
  schema: ZodType<T>
): ValidationResult<T> {
  const raw: Record<string, string | string[]> = {};
  for (const key of new Set(searchParams.keys())) {
    const all = searchParams.getAll(key);
    raw[key] = all.length > 1 ? all : all[0];
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    return failure(validationErrorResponse(result.error));
  }
  return { success: true, data: result.data };
}

export { z };
