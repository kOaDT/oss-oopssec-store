"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";

interface Wishlist {
  id: string;
  name: string;
  items: Array<{ id: string; product: { id: string } }>;
}

interface AddToWishlistButtonProps {
  productId: string;
}

export default function AddToWishlistButton({
  productId,
}: AddToWishlistButtonProps) {
  const { user } = useAuth();
  const router = useRouter();
  const [wishlists, setWishlists] = useState<Wishlist[]>([]);
  const [showDropdown, setShowDropdown] = useState(false);
  const [isAdding, setIsAdding] = useState<string | null>(null);
  const [addedTo, setAddedTo] = useState<Set<string>>(new Set());

  const fetchWishlists = useCallback(async () => {
    if (!user) return;
    try {
      const data = await api.get<Wishlist[]>("/api/wishlists");
      setWishlists(data);
      const alreadyIn = new Set<string>();
      data.forEach((wl) => {
        if (wl.items.some((item) => item.product.id === productId)) {
          alreadyIn.add(wl.id);
        }
      });
      setAddedTo(alreadyIn);
    } catch {
      // silently fail
    }
  }, [user, productId]);

  useEffect(() => {
    if (showDropdown) {
      fetchWishlists();
    }
  }, [showDropdown, fetchWishlists]);

  const handleToggle = () => {
    if (!user) {
      router.push("/login");
      return;
    }
    setShowDropdown(!showDropdown);
  };

  const handleAddToWishlist = async (wishlistId: string) => {
    setIsAdding(wishlistId);
    try {
      await api.post(`/api/wishlists/${wishlistId}/items`, { productId });
      setAddedTo((prev) => new Set(prev).add(wishlistId));
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setAddedTo((prev) => new Set(prev).add(wishlistId));
      }
    } finally {
      setIsAdding(null);
    }
  };

  const isInAnyWishlist = addedTo.size > 0;

  return (
    <div className="relative">
      <button
        onClick={handleToggle}
        aria-label="Add to wishlist"
        className="ml-4 cursor-pointer rounded-lg border border-slate-200 p-2.5 transition-colors hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-700"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className={`h-5 w-5 ${isInAnyWishlist ? "text-pink-500" : "text-slate-400"}`}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 18.656 3.172 11.83a4 4 0 010-5.656z"
            clipRule="evenodd"
          />
        </svg>
      </button>

      {showDropdown && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setShowDropdown(false)}
          />
          <div className="absolute right-0 z-20 mt-2 w-64 rounded-xl border border-slate-200 bg-white p-3 shadow-lg dark:border-slate-700 dark:bg-slate-800">
            <p className="mb-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
              Add to Wishlist
            </p>
            {wishlists.length === 0 ? (
              <p className="py-2 text-sm text-slate-500 dark:text-slate-400">
                No wishlists yet.{" "}
                <button
                  onClick={() => {
                    setShowDropdown(false);
                    router.push("/wishlists");
                  }}
                  className="cursor-pointer font-medium text-primary-600 hover:underline dark:text-primary-400"
                >
                  Create one
                </button>
              </p>
            ) : (
              <div className="space-y-1">
                {wishlists.map((wl) => (
                  <button
                    key={wl.id}
                    onClick={() => handleAddToWishlist(wl.id)}
                    disabled={addedTo.has(wl.id) || isAdding === wl.id}
                    className="flex w-full cursor-pointer items-center justify-between rounded-lg px-3 py-2 text-left text-sm transition-colors hover:bg-slate-50 disabled:cursor-default disabled:opacity-60 dark:hover:bg-slate-700"
                  >
                    <span className="text-slate-700 dark:text-slate-300">
                      {wl.name}
                    </span>
                    {addedTo.has(wl.id) ? (
                      <svg
                        className="h-4 w-4 text-green-500"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    ) : isAdding === wl.id ? (
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary-600 border-r-transparent" />
                    ) : (
                      <svg
                        className="h-4 w-4 text-slate-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 4v16m8-8H4"
                        />
                      </svg>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
