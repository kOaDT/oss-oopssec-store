import { apiRequest } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const XSS_PAYLOAD =
  "<script>fetch('/xss-flag.txt').then(r=>r.text()).then(d=>console.log(d))</script>";

describe("Cross-Site Scripting (XSS)", () => {
  it("stores XSS payload in review without sanitization", async () => {
    const productsRes = await apiRequest<{ id: string }[]>("/api/products");
    expect(productsRes.status).toBe(200);
    const products = Array.isArray(productsRes.data) ? productsRes.data : [];
    const productId = products[0]?.id;
    expect(productId).toBeDefined();

    const createRes = await apiRequest<{ content: string }>(
      `/api/products/${productId}/reviews`,
      {
        method: "POST",
        body: JSON.stringify({
          content: XSS_PAYLOAD,
          author: "attacker",
        }),
      }
    );
    expect(createRes.status).toBe(201);
    expect(createRes.data).toHaveProperty("content", XSS_PAYLOAD);
  });

  it("serves XSS flag file with expected content", async () => {
    const res = await apiRequest<string>("/xss-flag.txt");
    expect(res.status).toBe(200);
    expect(typeof res.data).toBe("string");
    expect(res.data).toContain(FLAGS.CROSS_SITE_SCRIPTING_XSS);
  });

  it("returns review with script tag unsanitized in GET reviews", async () => {
    const productsRes = await apiRequest<{ id: string }[]>("/api/products");
    expect(productsRes.status).toBe(200);
    const products = Array.isArray(productsRes.data) ? productsRes.data : [];
    const productId = products[0]?.id;
    expect(productId).toBeDefined();

    await apiRequest(`/api/products/${productId}/reviews`, {
      method: "POST",
      body: JSON.stringify({
        content: XSS_PAYLOAD,
        author: "attacker",
      }),
    });

    const reviewsRes = await apiRequest<{ content: string }[]>(
      `/api/products/${productId}/reviews`
    );
    expect(reviewsRes.status).toBe(200);
    const reviews = Array.isArray(reviewsRes.data) ? reviewsRes.data : [];
    const hasScript = reviews.some((r) => r.content?.includes("<script>"));
    expect(hasScript).toBe(true);
  });
});
