import ProductCard from "./ProductCard";

interface Product {
  id: string;
  name: string;
  price: number;
  description: string | null;
  imageUrl: string;
}

interface ProductGridProps {
  products: Product[];
  title?: string;
  subtitle?: string;
}

export default function ProductGrid({
  products,
  title = "Our Products",
  subtitle,
}: ProductGridProps) {
  return (
    <section className="py-16 md:py-24">
      <div className="container mx-auto px-4">
        {(title || subtitle) && (
          <div className="mb-12 text-center">
            {title && (
              <h2 className="mb-3 text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100 md:text-4xl">
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="mx-auto max-w-2xl text-slate-600 dark:text-slate-400">
                {subtitle}
              </p>
            )}
          </div>
        )}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
          {products.map((product) => (
            <ProductCard
              key={product.id}
              id={product.id}
              name={product.name}
              price={product.price}
              imageUrl={product.imageUrl}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
