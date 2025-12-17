export default function Newsletter() {
  return (
    <section className="bg-gradient-to-r from-primary-500 to-secondary-500 py-16">
      <div className="container mx-auto px-4">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="mb-4 text-3xl font-bold text-white md:text-4xl">
            Stay Updated
          </h2>
          <p className="mb-8 text-lg text-primary-50">
            Subscribe to our newsletter and get exclusive offers, new product
            announcements, and special discounts delivered to your inbox.
          </p>
          <form className="flex flex-col gap-4 sm:flex-row sm:justify-center">
            <input
              type="email"
              placeholder="Enter your email"
              className="w-full flex-1 rounded-full border-0 bg-white px-6 py-4 text-base text-slate-900 placeholder-slate-400 shadow-lg backdrop-blur-sm focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-primary-500 sm:max-w-md"
              required
            />
            <button
              type="submit"
              className="cursor-pointer rounded-full bg-white px-8 py-4 text-base font-semibold text-primary-600 shadow-lg transition-all hover:scale-105 hover:bg-slate-50 hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-primary-500"
            >
              Subscribe
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
