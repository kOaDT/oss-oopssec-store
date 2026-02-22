const BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";

interface ApiResponse<T = unknown> {
  status: number;
  data: T;
  headers: Headers;
}

export async function apiRequest<T = unknown>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${BASE_URL}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  const contentType = response.headers.get("content-type");
  let data: T;
  if (contentType?.includes("application/json")) {
    data = (await response.json()) as T;
  } else {
    data = (await response.text()) as T;
  }

  return { status: response.status, data, headers: response.headers };
}

export function extractAuthTokenFromHeaders(headers: Headers): string | null {
  const setCookie = headers.get("set-cookie");
  if (!setCookie) return null;
  const match = setCookie.match(/authToken=([^;]+)/);
  return match ? match[1] : null;
}

export async function login(
  email: string,
  password: string
): Promise<string | null> {
  const response = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  return extractAuthTokenFromHeaders(response.headers);
}

export async function loginOrFail(
  email: string,
  password: string
): Promise<string> {
  const token = await login(email, password);
  if (!token) {
    throw new Error(`Login failed for ${email}: no authToken in response`);
  }
  return token;
}

export function authHeaders(token: string): Record<string, string> {
  return {
    Cookie: `authToken=${token}`,
  };
}

export const TEST_USERS = {
  alice: { email: "alice@example.com", password: "iloveduck" },
  bob: { email: "bob@example.com", password: "qwerty" },
  bruteForce: { email: "vis.bruta@example.com", password: "sunshine" },
  admin: { email: "admin@oss.com", password: "admin" },
} as const;

export function expectFlag(data: unknown, expectedFlag: string): void {
  expect(data).toHaveProperty("flag", expectedFlag);
}

export { BASE_URL };

export async function getFirstProductId(): Promise<string> {
  const { status, data } = await apiRequest<{ id: string }[]>("/api/products");
  expect(status).toBe(200);
  expect(Array.isArray(data)).toBe(true);
  expect((data as { id: string }[]).length).toBeGreaterThan(0);
  return (data as { id: string }[])[0].id;
}

export interface UploadResponse {
  message?: string;
  imageUrl?: string;
  productName?: string;
  flag?: string;
  error?: string;
}

export async function uploadImage(
  token: string,
  productId: string,
  file: File
): Promise<{ status: number; data: UploadResponse | string }> {
  const formData = new FormData();
  formData.append("image", file);

  const response = await fetch(
    `${BASE_URL}/api/admin/products/${productId}/image`,
    {
      method: "POST",
      headers: authHeaders(token),
      body: formData,
    }
  );

  const contentType = response.headers.get("content-type");
  const data: UploadResponse | string = contentType?.includes(
    "application/json"
  )
    ? await response.json()
    : await response.text();
  return { status: response.status, data };
}

export function createSvgFile(content: string, name = "image.svg"): File {
  return new File([content], name, { type: "image/svg+xml" });
}

export function createJpegFile(size = 100): File {
  const buffer = Buffer.alloc(size);
  buffer[0] = 0xff;
  buffer[1] = 0xd8;
  return new File([buffer], "image.jpg", { type: "image/jpeg" });
}

export async function waitForCondition<T>(
  fn: () => Promise<T>,
  predicate: (result: T) => boolean,
  { timeout = 5000, interval = 200 } = {}
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const result = await fn();
    if (predicate(result)) return result;
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  return fn();
}
