import { getBaseUrl } from "./config";
import { getAuthToken } from "./client-auth";

type RequestMethod = "GET" | "POST" | "PATCH" | "DELETE" | "PUT";

interface RequestOptions {
  method?: RequestMethod;
  body?: unknown;
  headers?: Record<string, string>;
  requireAuth?: boolean;
  cache?: RequestCache;
}

class ApiError extends Error {
  status: number;
  data?: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const {
    method = "GET",
    body,
    headers = {},
    requireAuth = true,
    cache,
  } = options;

  const baseUrl = getBaseUrl();
  const url = `${baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  const requestHeaders: HeadersInit = {
    "Content-Type": "application/json",
    ...headers,
  };

  if (requireAuth) {
    const token = getAuthToken();
    if (token) {
      requestHeaders.Authorization = `Bearer ${token}`;
    }
  }

  const fetchOptions: RequestInit = {
    method,
    headers: requestHeaders,
  };

  if (body) {
    fetchOptions.body = JSON.stringify(body);
  }

  if (cache !== undefined) {
    fetchOptions.cache = cache;
  }

  const response = await fetch(url, fetchOptions);

  let data: unknown;
  const contentType = response.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const errorMessage =
      typeof data === "object" && data !== null && "error" in data
        ? String(data.error)
        : `Request failed with status ${response.status}`;

    throw new ApiError(errorMessage, response.status, data);
  }

  return data as T;
}

export const api = {
  get: <T>(
    endpoint: string,
    options?: Omit<RequestOptions, "method" | "body">
  ) => apiRequest<T>(endpoint, { ...options, method: "GET" }),

  post: <T>(
    endpoint: string,
    body?: unknown,
    options?: Omit<RequestOptions, "method">
  ) => apiRequest<T>(endpoint, { ...options, method: "POST", body }),

  patch: <T>(
    endpoint: string,
    body?: unknown,
    options?: Omit<RequestOptions, "method">
  ) => apiRequest<T>(endpoint, { ...options, method: "PATCH", body }),

  put: <T>(
    endpoint: string,
    body?: unknown,
    options?: Omit<RequestOptions, "method">
  ) => apiRequest<T>(endpoint, { ...options, method: "PUT", body }),

  delete: <T>(
    endpoint: string,
    options?: Omit<RequestOptions, "method" | "body">
  ) => apiRequest<T>(endpoint, { ...options, method: "DELETE" }),
};

export { ApiError };
export type { RequestOptions };
