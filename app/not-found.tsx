import Link from "next/link";
import Header from "./components/Header";
import Footer from "./components/Footer";

const ASCII = `
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡤⠐⠊⠉⠉⠀⠀⠈⠑⠄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⠜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠖⠢⡀⠹⣄⠀⠀⠀⠀
⠀⠀⠀⡤⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠊⠀⠀⣾⣿⣦⠫⡆⠀⠀⠀
⠀⢀⡏⠀⢀⠴⠂⠉⠐⢦⣄⠀⠀⠀⡇⠀⠀⠀⠀⠉⠁⢣⠰⡀⠀⠀
⢰⢈⠃⠀⣿⣷⠄⠀⠀⠈⢸⠃⠀⠀⠈⢦⡀⠀⠀⠀⠀⠸⠀⢯⡄⠀
⢸⠏⠀⠀⢻⠁⠀⠀⠀⡠⠊⠀⠀⠀⠀⠀⠈⠁⠐⠒⠊⠀⠀⠈⣼⠀
⢸⠀⠀⠀⠈⠢⠤⠤⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀
⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢃⡆⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⡀⠀⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⡆
⠀⠈⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⣠⠃
⠀⠀⠘⡳⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⠀

`;

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-950">
      <Header />
      <main className="flex flex-1 flex-col items-center justify-center px-4 py-8">
        <div className="w-full max-w-4xl">
          <pre
            className="mb-8 overflow-x-auto text-center font-mono text-xs leading-tight text-primary-400 sm:text-sm"
            aria-label="ASCII art"
          >
            {ASCII}
          </pre>

          <div className="text-center">
            <h1 className="mb-4 text-6xl font-black text-primary-400 sm:text-8xl">
              404
            </h1>
            <h2 className="mb-2 text-2xl font-bold text-slate-100 sm:text-3xl">
              Page Not Found
            </h2>

            <div className="mt-8 flex flex-col items-center justify-center gap-4 sm:flex-row">
              <Link
                href="/"
                className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-6 py-3 font-medium text-white transition-all hover:bg-primary-500 hover:shadow-lg hover:shadow-primary-500/25"
              >
                <svg
                  className="h-5 w-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
                  />
                </svg>
                Back to Home
              </Link>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}
