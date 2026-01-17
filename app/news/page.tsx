import Header from "../components/Header";
import Footer from "../components/Footer";

const leakedData = [
  {
    email: "alice@example.com",
    passwordHash: "a22e69ce108be0e6eee294be7eb6c254",
  },
  {
    email: "bob@example.com",
    passwordHash: "d8578edf8458ce06fbc5bb76a58c5ca4",
  },
  {
    email: "vis.bruta@example.com",
    passwordHash: null,
  },
];

export default function News() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                News
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Latest updates and announcements
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl space-y-8">
            <article className="rounded-2xl border border-red-200 bg-red-50 p-8 dark:border-red-800/50 dark:bg-red-900/20">
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
                <div>
                  <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                    Important Security Notice
                  </h2>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Published by Fresh Products - January 15, 2025
                  </p>
                </div>
              </div>

              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="text-lg font-semibold">
                  Data Breach Notification
                </p>
                <p className="leading-relaxed">
                  We regret to inform our valued customers that Fresh Products
                  has experienced a security incident. On January 10, 2025, we
                  discovered that an unauthorized party gained access to our
                  customer database.
                </p>
                <p className="leading-relaxed">
                  We take this matter very seriously and have immediately
                  launched an investigation. We have also notified the relevant
                  authorities and are working with cybersecurity experts to
                  understand the full scope of this incident.
                </p>
                <p className="leading-relaxed">
                  We sincerely apologize for any inconvenience or concern this
                  may cause. The security and privacy of our customers is our
                  top priority, and we are taking all necessary steps to prevent
                  such incidents in the future.
                </p>
                <p className="leading-relaxed font-semibold">
                  If you have any questions or concerns, please contact our
                  support team immediately.
                </p>
              </div>
            </article>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <h3 className="mb-6 text-xl font-bold text-slate-900 dark:text-slate-100">
                Leaked Data Sample
              </h3>
              <p className="mb-6 text-sm text-slate-600 dark:text-slate-400">
                The following is a sample of the customer data that was
                compromised in the breach. This information has been made
                publicly available by the attackers.
              </p>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse border border-slate-300 dark:border-slate-700">
                  <thead>
                    <tr className="bg-slate-200 dark:bg-slate-700">
                      <th className="border border-slate-300 px-4 py-3 text-left text-sm font-semibold text-slate-900 dark:border-slate-600 dark:text-slate-100">
                        Email
                      </th>
                      <th className="border border-slate-300 px-4 py-3 text-left text-sm font-semibold text-slate-900 dark:border-slate-600 dark:text-slate-100">
                        Password Hash
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {leakedData.map((user, index) => (
                      <tr
                        key={index}
                        className="bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700/50"
                      >
                        <td className="border border-slate-300 px-4 py-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:text-slate-100">
                          {user.email}
                        </td>
                        <td className="border border-slate-300 px-4 py-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:text-slate-100">
                          {user.passwordHash || (
                            <span className="italic text-slate-500 dark:text-slate-400">
                              [REDACTED]
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
