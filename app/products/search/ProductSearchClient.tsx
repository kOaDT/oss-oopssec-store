"use client";

import { useState, useEffect, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import FlagDisplay from "../../components/FlagDisplay";
import { getBaseUrl } from "@/lib/config";

interface Product {
  id: number;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
}

const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

export default function ProductSearchClient() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const initialQuery = searchParams.get("q") || "";

  const [searchQuery, setSearchQuery] = useState(initialQuery);
  const [products, setProducts] = useState<Product[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [flag, setFlag] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  const fetchProducts = useCallback(async (query: string) => {
    if (!query.trim()) {
      setProducts([]);
      setHasSearched(false);
      return;
    }

    setError(null);
    setFlag(null);
    setIsLoading(true);
    setHasSearched(true);

    try {
      const baseUrl = getBaseUrl();
      const response = await fetch(
        `${baseUrl}/api/products/search?q=${encodeURIComponent(query)}`
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to search products");
      }

      const data = await response.json();
      const results = Array.isArray(data.products) ? data.products : [];

      if (data.flag) {
        setFlag(data.flag);
      }

      setProducts(results);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
      setProducts([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initialQuery) {
      fetchProducts(initialQuery);
    }
  }, [initialQuery, fetchProducts]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/products/search?q=${encodeURIComponent(searchQuery)}`);
      fetchProducts(searchQuery);
    }
  };

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8">
          <h2 className="mb-4 text-2xl font-bold text-slate-900 dark:text-slate-100">
            Search Products
          </h2>
          <p className="mb-6 text-slate-600 dark:text-slate-400">
            Find products by name or description.
          </p>

          <form onSubmit={handleSubmit} className="mb-8">
            <div className="flex flex-col gap-4 sm:flex-row">
              <div className="flex-1">
                <label
                  htmlFor="search"
                  className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Search Query
                </label>
                <input
                  id="search"
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Enter product name or keyword..."
                  className="w-full rounded-lg border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:focus:border-primary-400 dark:focus:ring-primary-400"
                />
              </div>
              <div className="flex items-end">
                <button
                  type="submit"
                  className="cursor-pointer rounded-lg bg-primary-600 px-6 py-2 font-medium text-white shadow-sm transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:bg-primary-500 dark:hover:bg-primary-600"
                >
                  Search
                </button>
              </div>
            </div>
          </form>

          {error && (
            <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400">
              {error}
            </div>
          )}

          {flag && (
            <div className="mb-6">
              <FlagDisplay flag={flag} title="Flag Retrieved" />
            </div>
          )}

          {isLoading && (
            <div className="flex items-center justify-center py-20">
              <div className="text-center">
                <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
                <p className="text-slate-600 dark:text-slate-400">
                  Searching products...
                </p>
              </div>
            </div>
          )}

          {products.length > 0 && !isLoading && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                Search Results ({products.length})
              </h3>
              <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {products.map((product) => (
                  <Link
                    key={product.id}
                    href={`/products/${product.id}`}
                    className="group rounded-lg border border-slate-200 bg-white p-4 shadow-sm transition-all hover:shadow-md dark:border-slate-700 dark:bg-slate-800"
                  >
                    {product.imageUrl && isValidUrl(product.imageUrl) && (
                      <div className="relative mb-4 aspect-square overflow-hidden rounded-lg bg-slate-100 dark:bg-slate-700">
                        <Image
                          src={product.imageUrl}
                          alt={product.name || "Product"}
                          fill
                          className="object-cover transition-transform group-hover:scale-105"
                          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
                        />
                      </div>
                    )}
                    <h4 className="mb-2 font-semibold text-slate-900 group-hover:text-primary-600 dark:text-slate-100 dark:group-hover:text-primary-400">
                      {product.name}
                    </h4>
                    <p className="mb-3 line-clamp-2 text-sm text-slate-600 dark:text-slate-400">
                      {product.description}
                    </p>
                    <p className="text-lg font-bold text-primary-600 dark:text-primary-400">
                      $
                      {typeof product.price === "number"
                        ? product.price.toFixed(2)
                        : product.price}
                    </p>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {products.length === 0 && !isLoading && !error && hasSearched && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
              <p className="text-slate-600 dark:text-slate-400">
                No products found matching your search.
              </p>
            </div>
          )}

          {!hasSearched && !isLoading && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
              <p className="text-slate-600 dark:text-slate-400">
                Enter a search term to find products.
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
