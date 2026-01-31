"use client";

import { useState, useEffect, useCallback } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { getStoredUser } from "@/lib/client-auth";
import FlagDisplay from "../components/FlagDisplay";

interface WishlistProduct {
  id: string;
  name: string;
  price: number;
  imageUrl: string;
  description: string | null;
}

interface WishlistItem {
  id: string;
  addedAt: string;
  product: WishlistProduct;
}

interface Wishlist {
  id: string;
  name: string;
  ownerEmail?: string;
  isPublic: boolean;
  note: string | null;
  createdAt: string;
  updatedAt: string;
  items: WishlistItem[];
  flag?: string;
}

export default function WishlistClient() {
  const [wishlists, setWishlists] = useState<Wishlist[]>([]);
  const [selectedWishlist, setSelectedWishlist] = useState<Wishlist | null>(
    null
  );
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [newWishlistName, setNewWishlistName] = useState("");
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [removingItemId, setRemovingItemId] = useState<string | null>(null);
  const router = useRouter();

  const fetchWishlists = useCallback(async () => {
    try {
      const data = await api.get<Wishlist[]>("/api/wishlists");
      setWishlists(data);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        router.push("/login");
      }
    } finally {
      setIsLoading(false);
    }
  }, [router]);

  const fetchWishlistDetail = useCallback(
    async (id: string) => {
      try {
        const data = await api.get<Wishlist>(`/api/wishlists/${id}`);
        setSelectedWishlist(data);
      } catch (error) {
        if (error instanceof ApiError) {
          if (error.status === 401) {
            router.push("/login");
            return;
          }
          if (error.status === 404) {
            setSelectedWishlist(null);
            return;
          }
        }
      }
    },
    [router]
  );

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }
    fetchWishlists();
  }, [router, fetchWishlists]);

  const handleCreateWishlist = async () => {
    if (!newWishlistName.trim()) return;
    setIsCreating(true);
    try {
      await api.post("/api/wishlists", { name: newWishlistName.trim() });
      setNewWishlistName("");
      setShowCreateForm(false);
      await fetchWishlists();
    } catch (error) {
      console.error("Error creating wishlist:", error);
    } finally {
      setIsCreating(false);
    }
  };

  const handleDeleteWishlist = async (id: string) => {
    try {
      await api.delete(`/api/wishlists/${id}`);
      if (selectedWishlist?.id === id) {
        setSelectedWishlist(null);
      }
      await fetchWishlists();
    } catch (error) {
      console.error("Error deleting wishlist:", error);
    }
  };

  const handleRemoveItem = async (wishlistId: string, itemId: string) => {
    setRemovingItemId(itemId);
    try {
      await api.delete(`/api/wishlists/${wishlistId}/items/${itemId}`);
      await fetchWishlistDetail(wishlistId);
      await fetchWishlists();
    } catch (error) {
      console.error("Error removing item:", error);
    } finally {
      setRemovingItemId(null);
    }
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading wishlists...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (selectedWishlist) {
    return (
      <section className="container mx-auto px-4 py-8 lg:px-6 lg:py-12">
        <div className="mx-auto max-w-4xl">
          <button
            onClick={() => setSelectedWishlist(null)}
            className="mb-6 flex cursor-pointer items-center gap-2 text-sm font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            <svg
              className="h-4 w-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 19l-7-7 7-7"
              />
            </svg>
            Back to Wishlists
          </button>

          {selectedWishlist.flag && (
            <FlagDisplay flag={selectedWishlist.flag} title="Flag Retrieved!" />
          )}

          <div className="mb-8 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  {selectedWishlist.name}
                </h2>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  {selectedWishlist.items.length} item
                  {selectedWishlist.items.length !== 1 ? "s" : ""} &middot;
                  Created{" "}
                  {new Date(selectedWishlist.createdAt).toLocaleDateString()}
                </p>
              </div>
              <span
                className={`rounded-full px-3 py-1 text-xs font-semibold ${
                  selectedWishlist.isPublic
                    ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300"
                    : "bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300"
                }`}
              >
                {selectedWishlist.isPublic ? "Public" : "Private"}
              </span>
            </div>
          </div>

          {selectedWishlist.items.length === 0 ? (
            <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
              <h3 className="mb-3 text-xl font-bold text-slate-900 dark:text-slate-100">
                This wishlist is empty
              </h3>
              <p className="mb-6 text-slate-600 dark:text-slate-400">
                Browse products and add them to this wishlist.
              </p>
              <Link
                href="/"
                className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                Browse Products
              </Link>
            </div>
          ) : (
            <div className="space-y-4">
              {selectedWishlist.items.map((item) => (
                <div
                  key={item.id}
                  className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800"
                >
                  <div className="flex flex-col gap-4 sm:flex-row">
                    <Link
                      href={`/products/${item.product.id}`}
                      className="relative aspect-square h-28 w-28 flex-shrink-0 cursor-pointer overflow-hidden rounded-xl bg-slate-100 dark:bg-slate-700"
                    >
                      <Image
                        src={item.product.imageUrl}
                        alt={item.product.name}
                        fill
                        className="object-cover object-center"
                        sizes="112px"
                      />
                    </Link>

                    <div className="flex flex-1 items-center justify-between">
                      <div>
                        <Link
                          href={`/products/${item.product.id}`}
                          className="mb-1 block cursor-pointer text-lg font-semibold text-slate-900 transition-colors hover:text-primary-600 dark:text-slate-100 dark:hover:text-primary-400"
                        >
                          {item.product.name}
                        </Link>
                        <p className="mb-2 text-xl font-bold text-primary-600 dark:text-primary-400">
                          ${item.product.price.toFixed(2)}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          Added {new Date(item.addedAt).toLocaleDateString()}
                        </p>
                      </div>

                      <button
                        onClick={() =>
                          handleRemoveItem(selectedWishlist.id, item.id)
                        }
                        disabled={removingItemId === item.id}
                        className="flex cursor-pointer items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400 dark:hover:bg-red-900/30"
                        aria-label="Remove from wishlist"
                      >
                        <svg
                          className="h-4 w-4"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-8 lg:px-6 lg:py-12">
      <div className="mx-auto max-w-4xl">
        <div className="mb-8 flex items-center justify-between">
          <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
            Your Wishlists ({wishlists.length})
          </h2>
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="cursor-pointer rounded-xl bg-primary-600 px-5 py-2.5 text-sm font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
          >
            {showCreateForm ? "Cancel" : "New Wishlist"}
          </button>
        </div>

        {showCreateForm && (
          <div className="mb-8 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
            <h3 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
              Create New Wishlist
            </h3>
            <div className="flex gap-3">
              <input
                type="text"
                value={newWishlistName}
                onChange={(e) => setNewWishlistName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreateWishlist();
                }}
                placeholder="Wishlist name..."
                className="flex-1 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
              />
              <button
                onClick={handleCreateWishlist}
                disabled={isCreating || !newWishlistName.trim()}
                className="cursor-pointer rounded-lg bg-primary-600 px-6 py-2.5 font-semibold text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isCreating ? "Creating..." : "Create"}
              </button>
            </div>
          </div>
        )}

        {wishlists.length === 0 && !showCreateForm ? (
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <div className="mb-6 inline-flex h-20 w-20 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700">
              <svg
                className="h-10 w-10 text-slate-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"
                />
              </svg>
            </div>
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              No wishlists yet
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              Create your first wishlist to start saving your favorite products.
            </p>
            <button
              onClick={() => setShowCreateForm(true)}
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Create Wishlist
            </button>
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {wishlists.map((wishlist) => (
              <div
                key={wishlist.id}
                className="group rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition-shadow hover:shadow-md dark:border-slate-700 dark:bg-slate-800"
              >
                <div className="mb-4 flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                      {wishlist.name}
                    </h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      {wishlist.items.length} item
                      {wishlist.items.length !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteWishlist(wishlist.id);
                    }}
                    className="cursor-pointer rounded-lg p-2 text-slate-400 opacity-0 transition-all hover:bg-red-50 hover:text-red-600 group-hover:opacity-100 dark:hover:bg-red-900/20 dark:hover:text-red-400"
                    aria-label="Delete wishlist"
                  >
                    <svg
                      className="h-4 w-4"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>

                {wishlist.items.length > 0 && (
                  <div className="mb-4 flex -space-x-2">
                    {wishlist.items.slice(0, 4).map((item) => (
                      <div
                        key={item.id}
                        className="relative h-10 w-10 overflow-hidden rounded-full border-2 border-white bg-slate-100 dark:border-slate-800 dark:bg-slate-700"
                      >
                        <Image
                          src={item.product.imageUrl}
                          alt={item.product.name}
                          fill
                          className="object-cover"
                          sizes="40px"
                        />
                      </div>
                    ))}
                    {wishlist.items.length > 4 && (
                      <div className="flex h-10 w-10 items-center justify-center rounded-full border-2 border-white bg-slate-100 text-xs font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-700 dark:text-slate-300">
                        +{wishlist.items.length - 4}
                      </div>
                    )}
                  </div>
                )}

                <button
                  onClick={() => fetchWishlistDetail(wishlist.id)}
                  className="w-full cursor-pointer rounded-lg border border-slate-200 bg-slate-50 px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                >
                  View Wishlist
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
