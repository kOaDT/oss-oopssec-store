import Header from "../../components/Header";
import Footer from "../../components/Footer";
import { notFound } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { readFile } from "fs/promises";
import { join } from "path";
import { getBaseUrl, DOCS_BASE_URL } from "@/lib/config";
import { formatSlug, CATEGORY_LABELS } from "@/lib/format";
import type { Flag } from "@/lib/types";

interface VulnerabilityPageProps {
  params: Promise<{ slug: string }>;
}

async function getFlagBySlug(slug: string): Promise<Flag | null> {
  try {
    const baseUrl = getBaseUrl();
    const response = await fetch(`${baseUrl}/api/flags/${slug}`, {
      cache: "no-store",
    });

    if (!response.ok) {
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching flag:", error);
    return null;
  }
}

async function getMarkdownContent(filename: string): Promise<string> {
  try {
    const filePath = join(
      process.cwd(),
      "content",
      "vulnerabilities",
      filename
    );
    const content = await readFile(filePath, "utf-8");
    return content;
  } catch {
    throw new Error(`Failed to read markdown file: ${filename}`);
  }
}

export async function generateMetadata({
  params,
}: VulnerabilityPageProps): Promise<{ title: string; description: string }> {
  const { slug } = await params;
  const flag = await getFlagBySlug(slug);

  if (!flag) {
    return {
      title: "Vulnerability Not Found",
      description: "The requested vulnerability could not be found",
    };
  }

  return {
    title: `${flag.flag} - ${flag.cve || "Vulnerability"}`,
    description: `Learn about the ${flag.slug} vulnerability`,
  };
}

export default async function VulnerabilityPage({
  params,
}: VulnerabilityPageProps) {
  const { slug } = await params;
  const flag = await getFlagBySlug(slug);

  if (!flag) {
    notFound();
  }

  const markdownContent = await getMarkdownContent(flag.markdownFile);

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <p className="mb-3 text-sm font-medium uppercase tracking-wider text-white/70">
                {CATEGORY_LABELS[flag.category]}
              </p>
              <div className="flex items-center justify-center gap-3">
                <h1 className="text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                  {formatSlug(flag.slug)}
                </h1>
                {flag.cve && (
                  <span className="rounded-full bg-red-100 px-3 py-1 text-xs font-semibold text-red-800 dark:bg-red-900/30 dark:text-red-400">
                    {flag.cve}
                  </span>
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl">
            {flag.walkthroughSlug && (
              <a
                href={`${DOCS_BASE_URL}/${flag.walkthroughSlug}`}
                target="_blank"
                rel="noopener noreferrer"
                className="mb-8 flex items-center justify-between gap-4 rounded-lg border border-primary-200 bg-primary-50 px-5 py-4 transition-colors hover:bg-primary-100 dark:border-primary-800 dark:bg-primary-950/40 dark:hover:bg-primary-900/40"
              >
                <div>
                  <p className="font-semibold text-slate-900 dark:text-slate-100">
                    Want to see the exploit in action?
                  </p>
                  <p className="text-sm text-slate-700 dark:text-slate-300">
                    Full writeup with payloads and screenshots on the
                    walkthrough site.
                  </p>
                </div>
                <svg
                  className="h-5 w-5 shrink-0 text-primary-600 dark:text-primary-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M14 5l7 7m0 0l-7 7m7-7H3"
                  />
                </svg>
              </a>
            )}
            <article className="p-8">
              <div className="markdown-content">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    h1: ({ children }) => (
                      <h1 className="mb-6 text-3xl font-bold text-slate-900 dark:text-slate-100">
                        {children}
                      </h1>
                    ),
                    h2: ({ children }) => (
                      <h2 className="mb-4 mt-8 text-2xl font-bold text-slate-900 dark:text-slate-100">
                        {children}
                      </h2>
                    ),
                    h3: ({ children }) => (
                      <h3 className="mb-3 mt-6 text-xl font-semibold text-slate-900 dark:text-slate-100">
                        {children}
                      </h3>
                    ),
                    p: ({ children }) => (
                      <p className="mb-4 leading-relaxed text-slate-700 dark:text-slate-300">
                        {children}
                      </p>
                    ),
                    ul: ({ children }) => (
                      <ul className="mb-4 ml-6 list-disc space-y-2 text-slate-700 dark:text-slate-300">
                        {children}
                      </ul>
                    ),
                    ol: ({ children }) => (
                      <ol className="mb-4 ml-6 list-decimal space-y-2 text-slate-700 dark:text-slate-300">
                        {children}
                      </ol>
                    ),
                    li: ({ children }) => (
                      <li className="leading-relaxed">{children}</li>
                    ),
                    code: ({ children, className }) => {
                      const isInline = !className;
                      return isInline ? (
                        <code className="rounded bg-slate-100 px-1.5 py-0.5 text-sm font-mono text-primary-600 dark:bg-slate-700 dark:text-primary-400">
                          {children}
                        </code>
                      ) : (
                        <code className={className}>{children}</code>
                      );
                    },
                    pre: ({ children }) => (
                      <pre className="mb-4 overflow-x-auto rounded-lg bg-slate-900 p-4 dark:bg-slate-950">
                        {children}
                      </pre>
                    ),
                    a: ({ href, children }) => (
                      <a
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-medium text-primary-600 underline transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                      >
                        {children}
                      </a>
                    ),
                    strong: ({ children }) => (
                      <strong className="font-semibold text-slate-900 dark:text-slate-100">
                        {children}
                      </strong>
                    ),
                    blockquote: ({ children }) => (
                      <blockquote className="my-4 border-l-4 border-primary-500 bg-slate-50 pl-4 italic text-slate-700 dark:border-primary-400 dark:bg-slate-800 dark:text-slate-300">
                        {children}
                      </blockquote>
                    ),
                  }}
                >
                  {markdownContent}
                </ReactMarkdown>
              </div>
            </article>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
