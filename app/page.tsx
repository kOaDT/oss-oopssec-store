import Header from "./components/Header";
import Hero from "./components/Hero";
import ProductGrid from "./components/ProductGrid";
import Features from "./components/Features";
import Newsletter from "./components/Newsletter";
import Footer from "./components/Footer";
import { getBaseUrl } from "@/lib/config";
import type { Product } from "@/lib/types";

async function getProducts(): Promise<Product[]> {
  const baseUrl = getBaseUrl();
  const res = await fetch(`${baseUrl}/api/products`, {
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error("Failed to fetch products");
  }

  return res.json();
}

export default async function Home() {
  const products = await getProducts();
  const featuredProducts = products.slice(0, 10);
  const newProducts = products.slice(10, 17);

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <Hero />
        <ProductGrid
          products={featuredProducts}
          title="Featured Products"
          subtitle="Handpicked selection of our most popular items"
        />
        <Features />
        {newProducts.length > 0 && (
          <ProductGrid
            products={newProducts}
            title="New Arrivals"
            subtitle="Discover our latest additions to the collection"
          />
        )}
        <Newsletter />
      </main>
      <Footer />
    </div>
  );
}
