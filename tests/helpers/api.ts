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

export async function login(
  email: string,
  password: string
): Promise<string | null> {
  const response = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) return null;

  const match = setCookie.match(/authToken=([^;]+)/);
  return match ? match[1] : null;
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
