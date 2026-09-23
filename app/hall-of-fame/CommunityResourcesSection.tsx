import type { ComponentType } from "react";
import type { CommunityResource, CommunityResourceType } from "@/lib/types";
import { formatDateUTC } from "@/lib/format";
import {
  ArticleIcon,
  CourseIcon,
  ExternalLinkIcon,
  MegaphoneIcon,
  TalkIcon,
  VideoIcon,
  type IconProps,
} from "./icons";

interface CommunityResourcesSectionProps {
  resources: CommunityResource[];
}

const RESOURCE_TYPES: Record<
  CommunityResourceType,
  { label: string; Icon: ComponentType<IconProps> }
> = {
  video: { label: "Video", Icon: VideoIcon },
  article: { label: "Article", Icon: ArticleIcon },
  talk: { label: "Talk", Icon: TalkIcon },
  course: { label: "Course", Icon: CourseIcon },
};

const languageNames = new Intl.DisplayNames(["en"], { type: "language" });

function MetaSeparator({ className = "" }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`mx-2 text-slate-300 dark:text-slate-600 ${className}`}
    >
      •
    </span>
  );
}

function ResourceItem({ resource }: { resource: CommunityResource }) {
  const { label, Icon } = RESOURCE_TYPES[resource.type];
  const publishedOn = formatDateUTC(resource.date);

  return (
    <li>
      <a
        href={resource.url}
        target="_blank"
        rel="noopener noreferrer"
        className="group flex gap-4 px-5 py-5 transition-colors hover:bg-slate-50 focus-visible:bg-slate-50 focus-visible:outline-none dark:hover:bg-slate-700/40 dark:focus-visible:bg-slate-700/40 sm:px-6"
      >
        <span
          className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center bg-slate-100 text-slate-500 transition-colors group-hover:bg-primary-50 group-hover:text-primary-600 dark:bg-slate-700/60 dark:text-slate-400 dark:group-hover:bg-primary-900/30 dark:group-hover:text-primary-400"
          style={{ borderRadius: "8px" }}
        >
          <Icon className="h-5 w-5" />
        </span>

        <span className="flex min-w-0 flex-1 items-baseline justify-between gap-6">
          <span className="min-w-0">
            <span className="block font-medium leading-snug text-slate-900 transition-colors group-hover:text-primary-600 dark:text-slate-100 dark:group-hover:text-primary-400">
              <span lang={resource.language}>{resource.title}</span>
              <span className="sr-only"> (opens in a new tab)</span>
              <ExternalLinkIcon className="ml-1.5 inline h-3.5 w-3.5 align-[-0.1em] text-slate-400 transition-colors group-hover:text-primary-600 dark:text-slate-500 dark:group-hover:text-primary-400" />
            </span>

            <span className="mt-1.5 block text-sm text-slate-500 dark:text-slate-400">
              <span className="block sm:inline">{resource.author}</span>
              <MetaSeparator className="hidden sm:inline" />
              {label}
              {resource.language && (
                <>
                  <MetaSeparator />
                  {languageNames.of(resource.language)}
                </>
              )}
            </span>

            <span className="mt-1 block text-sm text-slate-400 dark:text-slate-500 sm:hidden">
              {publishedOn}
            </span>
          </span>

          <span className="hidden shrink-0 text-sm tabular-nums text-slate-400 dark:text-slate-500 sm:block">
            {publishedOn}
          </span>
        </span>
      </a>
    </li>
  );
}

export default function CommunityResourcesSection({
  resources,
}: CommunityResourcesSectionProps) {
  if (resources.length === 0) {
    return null;
  }

  const sorted = [...resources].sort((a, b) => b.date.localeCompare(a.date));

  return (
    <section className="container mx-auto px-4 pb-16 md:pb-20">
      <div className="mx-auto max-w-3xl">
        <div className="mb-12 text-center">
          <div
            className="mb-6 inline-flex items-center justify-center bg-primary-100 p-4 dark:bg-primary-900/30"
            style={{ borderRadius: "8px" }}
          >
            <MegaphoneIcon className="h-8 w-8 text-primary-600 dark:text-primary-400" />
          </div>
          <h2 className="mb-3 text-4xl font-light tracking-tight text-slate-900 dark:text-slate-100 md:text-5xl">
            Community Resources
          </h2>
          <p className="mx-auto max-w-2xl text-lg text-slate-600 dark:text-slate-400">
            Courses, talks and write-ups built on OopsSec Store by the
            community.
          </p>
        </div>

        <ul
          className="divide-y divide-slate-200 overflow-hidden bg-white shadow-md dark:divide-slate-700 dark:bg-slate-800"
          style={{ borderRadius: "8px" }}
        >
          {sorted.map((resource) => (
            <ResourceItem key={resource.url} resource={resource} />
          ))}
        </ul>
      </div>
    </section>
  );
}
