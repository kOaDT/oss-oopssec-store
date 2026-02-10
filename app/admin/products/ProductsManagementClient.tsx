"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getBaseUrl } from "@/lib/config";
import { getStoredUser } from "@/lib/client-auth";
import FlagDisplay from "../../components/FlagDisplay";
import type { Product } from "@/lib/types";

export default function ProductsManagementClient() {
  const [products, setProducts] = useState<Product[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadingProductId, setUploadingProductId] = useState<string | null>(
    null
  );
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const [flag, setFlag] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const fileInputRefs = useRef<{ [key: string]: HTMLInputElement | null }>({});
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const fetchProducts = async () => {
      try {
        const baseUrl = getBaseUrl();

        const response = await fetch(`${baseUrl}/api/admin/products`, {
          credentials: "include",
        });

        if (!response.ok) {
          if (response.status === 401) {
            router.push("/login");
            return;
          }
          if (response.status === 403) {
            setError("Forbidden: You do not have administrator privileges.");
            setIsLoading(false);
            return;
          }
          throw new Error("Failed to fetch products");
        }

        const data = await response.json();
        setProducts(data);
      } catch (error) {
        console.error("Error fetching products:", error);
        setError("An error occurred while fetching products.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchProducts();
  }, [router]);

  useEffect(() => {
    if (flag) {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [flag]);

  const handleFileSelect = (productId: string) => {
    const input = fileInputRefs.current[productId];
    if (input) {
      input.click();
    }
  };

  const handleFileChange = async (
    productId: string,
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadingProductId(productId);
    setUploadSuccess(null);
    setError(null);

    try {
      const baseUrl = getBaseUrl();

      const formData = new FormData();
      formData.append("image", file);

      const response = await fetch(
        `${baseUrl}/api/admin/products/${productId}/image`,
        {
          method: "POST",
          credentials: "include",
          body: formData,
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to upload image");
      }

      const result = await response.json();

      setProducts((prev) =>
        prev.map((p) =>
          p.id === productId ? { ...p, imageUrl: result.imageUrl } : p
        )
      );

      setUploadSuccess(`Image uploaded successfully for ${result.productName}`);

      if (result.flag) {
        setFlag(result.flag);
      }

      if (event.target) {
        event.target.value = "";
      }
    } catch (error) {
      console.error("Error uploading image:", error);
      setError(
        error instanceof Error ? error.message : "Failed to upload image"
      );
    } finally {
      setUploadingProductId(null);
    }
  };

  const openPreview = (imageUrl: string) => {
    setPreviewUrl(imageUrl);
  };

  const closePreview = () => {
    setPreviewUrl(null);
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-6xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading products...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (error && products.length === 0) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
              <svg
                className="h-8 w-8 text-red-600 dark:text-red-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </div>
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Access Denied
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">{error}</p>
            <Link
              href="/admin"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Back to Admin
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
              Product Images
            </h2>
            <Link
              href="/admin"
              className="cursor-pointer rounded-lg bg-slate-100 px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
            >
              ← Back to Dashboard
            </Link>
          </div>

          {flag && (
            <FlagDisplay
              flag={flag}
              description="You successfully exploited the malicious file upload vulnerability!"
              showIcon
            />
          )}

          {uploadSuccess && (
            <div className="mb-6 rounded-xl border-2 border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-900/20">
              <p className="text-center text-sm font-medium text-green-700 dark:text-green-300">
                {uploadSuccess}
              </p>
            </div>
          )}

          {error && (
            <div className="mb-6 rounded-xl border-2 border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
              <p className="text-center text-sm text-red-700 dark:text-red-300">
                {error}
              </p>
            </div>
          )}

          <div className="mb-6 rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900/50">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              <span className="font-semibold">Supported formats:</span> JPEG,
              PNG, GIF, WebP, SVG
            </p>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              <span className="font-semibold">Max file size:</span> 5MB
            </p>
          </div>

          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {products.map((product) => (
              <div
                key={product.id}
                className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800"
              >
                <div
                  className="relative aspect-square cursor-pointer overflow-hidden bg-slate-100 dark:bg-slate-700"
                  onClick={() => openPreview(product.imageUrl)}
                >
                  {product.imageUrl.startsWith("/api/uploads/") ? (
                    <object
                      data={product.imageUrl}
                      type="image/svg+xml"
                      className="h-full w-full object-cover"
                    >
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src={product.imageUrl}
                        alt={product.name}
                        className="h-full w-full object-cover"
                      />
                    </object>
                  ) : (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={product.imageUrl}
                      alt={product.name}
                      className="h-full w-full object-cover"
                    />
                  )}
                  <div className="absolute inset-0 flex items-center justify-center bg-black/0 transition-all hover:bg-black/20">
                    <span className="rounded-lg bg-black/60 px-3 py-1.5 text-xs font-medium text-white opacity-0 transition-opacity hover:opacity-100">
                      Click to preview
                    </span>
                  </div>
                </div>
                <div className="p-4">
                  <h3 className="mb-1 truncate font-semibold text-slate-900 dark:text-slate-100">
                    {product.name}
                  </h3>
                  <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">
                    ${product.price.toFixed(2)}
                  </p>
                  <input
                    ref={(el) => {
                      fileInputRefs.current[product.id] = el;
                    }}
                    type="file"
                    accept="image/*"
                    onChange={(e) => handleFileChange(product.id, e)}
                    className="hidden"
                  />
                  <button
                    onClick={() => handleFileSelect(product.id)}
                    disabled={uploadingProductId === product.id}
                    className="w-full cursor-pointer rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-all hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
                  >
                    {uploadingProductId === product.id
                      ? "Uploading..."
                      : "Upload New Image"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {previewUrl && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
          onClick={closePreview}
        >
          <div className="relative max-h-[90vh] max-w-[90vw]">
            <button
              onClick={closePreview}
              className="absolute -right-4 -top-4 cursor-pointer rounded-full bg-white p-2 shadow-lg transition-transform hover:scale-110 dark:bg-slate-800"
            >
              <svg
                className="h-6 w-6 text-slate-600 dark:text-slate-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
            {previewUrl.startsWith("/api/uploads/") ? (
              <object
                data={previewUrl}
                type="image/svg+xml"
                className="max-h-[85vh] max-w-[85vw] rounded-lg"
                onClick={(e) => e.stopPropagation()}
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={previewUrl}
                  alt="Preview"
                  className="max-h-[85vh] max-w-[85vw] rounded-lg"
                />
              </object>
            ) : (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={previewUrl}
                alt="Preview"
                className="max-h-[85vh] max-w-[85vw] rounded-lg"
                onClick={(e) => e.stopPropagation()}
              />
            )}
          </div>
        </div>
      )}
    </section>
  );
}
