"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { getStoredUser } from "@/lib/utils/auth";
import { getBaseUrl } from "@/lib/config";

export default function CartButton() {
  const [cartCount, setCartCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      setIsLoading(false);
      return;
    }

    const fetchCartCount = async () => {
      try {
        const baseUrl = getBaseUrl();
        const token = localStorage.getItem("authToken");

        const response = await fetch(`${baseUrl}/api/cart`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          const totalItems = data.cartItems.reduce(
            (sum: number, item: { quantity: number }) => sum + item.quantity,
            0
          );
          setCartCount(totalItems);
        }
      } catch (error) {
        console.error("Error fetching cart count:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchCartCount();

    const interval = setInterval(fetchCartCount, 5000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleStorageChange = () => {
      const user = getStoredUser();
      if (user) {
        const fetchCartCount = async () => {
          try {
            const baseUrl = getBaseUrl();
            const token = localStorage.getItem("authToken");

            const response = await fetch(`${baseUrl}/api/cart`, {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            });

            if (response.ok) {
              const data = await response.json();
              const totalItems = data.cartItems.reduce(
                (sum: number, item: { quantity: number }) =>
                  sum + item.quantity,
                0
              );
              setCartCount(totalItems);
            }
          } catch (error) {
            console.error("Error fetching cart count:", error);
          }
        };
        fetchCartCount();
      } else {
        setCartCount(0);
      }
    };

    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, []);

  const user = getStoredUser();
  if (!user) {
    return null;
  }

  return (
    <Link
      href="/cart"
      className="relative cursor-pointer rounded-full p-2 text-slate-700 transition-colors hover:bg-slate-100 hover:text-primary-600 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-primary-400"
      aria-label="Shopping cart"
    >
      <svg
        className="h-6 w-6"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"
        />
      </svg>
      {!isLoading && cartCount > 0 && (
        <span className="absolute right-0 top-0 flex h-5 w-5 items-center justify-center rounded-full bg-primary-600 text-xs font-semibold text-white">
          {cartCount > 99 ? "99+" : cartCount}
        </span>
      )}
    </Link>
  );
}
