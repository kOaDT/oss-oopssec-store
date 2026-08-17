interface PageHeroProps {
  title: string;
  subtitle: string;
}

export default function PageHero({ title, subtitle }: PageHeroProps) {
  return (
    <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
      <div className="container mx-auto px-4 py-16 md:py-24">
        <div className="mx-auto max-w-3xl text-center">
          <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
            {title}
          </h1>
          <p className="text-lg text-primary-50 md:text-xl">{subtitle}</p>
        </div>
      </div>
    </section>
  );
}
