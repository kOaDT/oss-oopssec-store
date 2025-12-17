import Header from "../components/Header";
import Footer from "../components/Footer";

export default function Terms() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                Terms of Service
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Important information about the use of this application
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl space-y-12">
            <div className="rounded-2xl border border-red-200 bg-red-50 p-8 dark:border-red-800/50 dark:bg-red-900/20">
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
                  <svg
                    className="h-6 w-6 text-red-600 dark:text-red-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Educational Purpose Only
                </h2>
              </div>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="text-lg font-semibold">
                  This project is provided solely for educational purposes and
                  must not be deployed in a production environment.
                </p>
                <p className="leading-relaxed">
                  This application contains intentional security vulnerabilities
                  designed for educational and training purposes. It is intended
                  to help developers, security professionals, and students learn
                  about common web security issues, understand how
                  vulnerabilities can be exploited, and develop skills in secure
                  coding practices.
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Prohibited Uses
              </h2>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="leading-relaxed">
                  You are expressly prohibited from:
                </p>
                <ul className="ml-6 list-disc space-y-2">
                  <li>
                    Deploying this application to any production environment or
                    public-facing server
                  </li>
                  <li>
                    Using this application in any environment where it could be
                    accessed by unauthorized users
                  </li>
                  <li>
                    Using this application to process, store, or transmit real
                    user data or sensitive information
                  </li>
                  <li>
                    Using this application for any commercial purpose or as part
                    of any commercial service
                  </li>
                  <li>
                    Modifying this application to remove security warnings and
                    deploying it as a production system
                  </li>
                </ul>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Disclaimer of Liability
              </h2>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="leading-relaxed">
                  The authors, contributors, and maintainers of this project
                  expressly disclaim all liability for any damages, losses, or
                  consequences arising from the use, misuse, or deployment of
                  this application.
                </p>
                <p className="leading-relaxed">
                  By using this application, you acknowledge and agree that:
                </p>
                <ul className="ml-6 list-disc space-y-2">
                  <li>
                    This application is provided &quot;as is&quot; without any
                    warranties or guarantees of any kind
                  </li>
                  <li>
                    The authors and contributors are not responsible for any
                    security breaches, data loss, or other damages that may
                    result from using this application
                  </li>
                  <li>
                    You assume full responsibility for any consequences of
                    deploying or using this application
                  </li>
                  <li>
                    You will not hold the authors, contributors, or maintainers
                    liable for any direct, indirect, incidental, special, or
                    consequential damages
                  </li>
                </ul>
                <p className="leading-relaxed">
                  If you choose to deploy this application despite these
                  warnings, you do so entirely at your own risk and without any
                  recourse to the project maintainers or contributors.
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Acceptable Use
              </h2>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="leading-relaxed">
                  This application may only be used in:
                </p>
                <ul className="ml-6 list-disc space-y-2">
                  <li>
                    Isolated local development environments on your personal
                    machine
                  </li>
                  <li>
                    Controlled training labs with proper network isolation and
                    access controls
                  </li>
                  <li>
                    Private networks that are not accessible from the public
                    internet
                  </li>
                  <li>
                    Educational institutions with appropriate security measures
                    and supervision
                  </li>
                </ul>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Acknowledgment
              </h2>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="leading-relaxed">
                  By accessing or using this application, you acknowledge that
                  you have read, understood, and agree to be bound by these
                  Terms of Service. You understand that this application is for
                  educational purposes only and that deploying it in a
                  production environment is strictly prohibited.
                </p>
                <p className="leading-relaxed">
                  If you do not agree to these terms, you must immediately cease
                  using this application and remove it from any systems where it
                  has been installed.
                </p>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
