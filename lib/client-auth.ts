import type { User } from "./types";

export type { User };

export function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  const storedUser = localStorage.getItem("user");
  if (storedUser) {
    try {
      return JSON.parse(storedUser);
    } catch {
      localStorage.removeItem("user");
      return null;
    }
  }
  return null;
}

export function clearAuth(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("user");
}
