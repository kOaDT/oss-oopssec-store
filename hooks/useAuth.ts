"use client";

import { useState, useEffect } from "react";
import { getStoredUser, type User, clearAuth } from "@/lib/client-auth";

export function useAuth() {
  const [user, setUser] = useState<User | null>(() => getStoredUser());

  useEffect(() => {
    const handleStorageChange = () => {
      setUser(getStoredUser());
    };

    window.addEventListener("storage", handleStorageChange);
    const interval = setInterval(() => {
      const currentUser = getStoredUser();
      if (JSON.stringify(currentUser) !== JSON.stringify(user)) {
        setUser(currentUser);
      }
    }, 100);

    return () => {
      window.removeEventListener("storage", handleStorageChange);
      clearInterval(interval);
    };
  }, [user]);

  const logout = () => {
    clearAuth();
    setUser(null);
  };

  return { user, logout };
}
