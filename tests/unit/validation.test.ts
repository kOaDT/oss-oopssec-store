import {
  parseBody,
  parseFormData,
  parseQuery,
  validationErrorPayload,
  z,
} from "../../lib/validation";

const jsonRequest = (body: string | undefined): Request =>
  new Request("http://localhost/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

const formRequest = (body: string): Request =>
  new Request("http://localhost/test", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

const sampleSchema = z.object({
  email: z.string().email(),
  age: z.coerce.number().int().min(0).optional(),
});

describe("validationErrorPayload", () => {
  it("aplats the first issue message into the top-level error field", () => {
    const result = sampleSchema.safeParse({ email: "not-an-email" });
    expect(result.success).toBe(false);
    if (result.success) return;

    const payload = validationErrorPayload(result.error);
    expect(payload.error).toMatch(/email/i);
    expect(payload.details).toHaveLength(1);
    expect(payload.details[0]).toMatchObject({
      path: "email",
      message: expect.any(String),
      code: expect.any(String),
    });
  });

  it("falls back to a generic message when there are no issues", () => {
    const result = sampleSchema.safeParse({
      email: "ok@example.com",
      age: "abc",
    });
    expect(result.success).toBe(false);
    if (result.success) return;
    const payload = validationErrorPayload(result.error);
    expect(payload.error).toBeTruthy();
    expect(payload.details.length).toBeGreaterThan(0);
  });
});

describe("parseBody", () => {
  it("returns parsed data on success", async () => {
    const result = await parseBody(
      jsonRequest(JSON.stringify({ email: "ok@example.com" })),
      sampleSchema
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.email).toBe("ok@example.com");
  });

  it("returns 400 with structured error on schema failure", async () => {
    const result = await parseBody(
      jsonRequest(JSON.stringify({ email: "nope" })),
      sampleSchema
    );
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.response.status).toBe(400);
    const body = await result.response.json();
    expect(body.error).toMatch(/email/i);
    expect(Array.isArray(body.details)).toBe(true);
  });

  it("rejects an empty body by default with Invalid JSON body", async () => {
    const result = await parseBody(jsonRequest(""), sampleSchema);
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.response.status).toBe(400);
    const body = await result.response.json();
    expect(body.error).toBe("Invalid JSON body");
  });

  it("accepts an empty body when allowEmptyBody is true and applies schema defaults", async () => {
    const schema = z.object({ name: z.string().default("anon") });
    const result = await parseBody(jsonRequest(""), schema, {
      allowEmptyBody: true,
    });
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data).toEqual({ name: "anon" });
  });

  it("returns Invalid JSON body for malformed JSON", async () => {
    const result = await parseBody(jsonRequest("{not json"), sampleSchema);
    expect(result.success).toBe(false);
    if (result.success) return;
    const body = await result.response.json();
    expect(body.error).toBe("Invalid JSON body");
  });
});

describe("parseFormData", () => {
  it("parses application/x-www-form-urlencoded into the schema shape", async () => {
    const result = await parseFormData(
      formRequest("email=ok%40example.com&age=42"),
      sampleSchema
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data).toEqual({ email: "ok@example.com", age: 42 });
  });

  it("returns 400 with first error message on validation failure", async () => {
    const result = await parseFormData(formRequest("email=bad"), sampleSchema);
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.response.status).toBe(400);
    const body = await result.response.json();
    expect(body.error).toMatch(/email/i);
  });

  it("collapses repeated keys into an array for the schema", async () => {
    const tagsSchema = z.object({ tag: z.array(z.string()) });
    const result = await parseFormData(
      formRequest("tag=a&tag=b&tag=c"),
      tagsSchema
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.tag).toEqual(["a", "b", "c"]);
  });
});

describe("parseQuery", () => {
  it("parses URLSearchParams into the schema shape", () => {
    const result = parseQuery(
      new URLSearchParams("email=ok@example.com&age=7"),
      sampleSchema
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data).toEqual({ email: "ok@example.com", age: 7 });
  });

  it("returns 400 on invalid query", () => {
    const result = parseQuery(new URLSearchParams("email=nope"), sampleSchema);
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.response.status).toBe(400);
  });

  it("collapses multi-value keys into an array", () => {
    const schema = z.object({ id: z.array(z.string()) });
    const result = parseQuery(new URLSearchParams("id=1&id=2&id=3"), schema);
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.id).toEqual(["1", "2", "3"]);
  });

  it("keeps a single-value key as a string", () => {
    const schema = z.object({ q: z.string() });
    const result = parseQuery(new URLSearchParams("q=hello"), schema);
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.q).toBe("hello");
  });
});
