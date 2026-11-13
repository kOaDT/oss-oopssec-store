import type { ReactNode } from "react";
import CopyButton from "../../login/CopyButton";
import { DOCS_AI_SETUP_URL } from "@/lib/config";
import type { LlmErrorCode } from "@/lib/llm";

const SETUP_CODES = [
  "llm_unreachable",
  "llm_model_not_found",
  "llm_unauthorized",
] as const satisfies readonly LlmErrorCode[];

export type SetupErrorCode = (typeof SETUP_CODES)[number];

export function isSetupErrorCode(code: unknown): code is SetupErrorCode {
  return SETUP_CODES.includes(code as SetupErrorCode);
}

interface ModelSetupPanelProps {
  code: SetupErrorCode;
  model: string;
  endpointHost: string;
}

interface PanelContent {
  title: string;
  body: ReactNode;
  command?: string;
}

const linkClassName =
  "font-medium text-primary-600 underline hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300";

const inlineCodeClassName =
  "rounded bg-amber-100 px-1 py-0.5 font-mono text-xs dark:bg-amber-900/40";

function panelContent(
  code: SetupErrorCode,
  model: string,
  endpointHost: string
): PanelContent {
  switch (code) {
    case "llm_unreachable":
      return {
        title: "OSSBot can't reach its language model",
        body: (
          <>
            Nothing is answering at{" "}
            <code className={inlineCodeClassName}>{endpointHost}</code>. OSSBot
            runs on a local model served by{" "}
            <a
              href="https://ollama.com/download"
              target="_blank"
              rel="noopener noreferrer"
              className={linkClassName}
            >
              Ollama
            </a>
            : start it, pull the model, then send your message again.
          </>
        ),
        command: `ollama pull ${model}`,
      };
    case "llm_model_not_found":
      return {
        title: `The ${model} model isn't available`,
        body: "Pull it into Ollama, then send your message again.",
        command: `ollama pull ${model}`,
      };
    case "llm_unauthorized":
      return {
        title: "The model provider rejected the API key",
        body: (
          <>
            Check <code className={inlineCodeClassName}>LLM_API_KEY</code> in
            the lab&apos;s environment, then restart the lab.
          </>
        ),
      };
  }
}

export default function ModelSetupPanel({
  code,
  model,
  endpointHost,
}: ModelSetupPanelProps) {
  const { title, body, command } = panelContent(code, model, endpointHost);

  return (
    <div
      role="alert"
      className="border-t border-amber-200 bg-amber-50 px-4 py-4 sm:px-6 dark:border-amber-800/50 dark:bg-amber-900/20"
    >
      <div className="flex gap-3">
        <svg
          className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        <div className="min-w-0 flex-1 space-y-2 text-sm">
          <p className="font-semibold text-slate-900 dark:text-white">
            {title}
          </p>
          <p className="text-slate-700 dark:text-slate-300">{body}</p>
          {command && (
            <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white py-1 pl-3 pr-1 dark:border-slate-700 dark:bg-slate-900">
              <code className="overflow-x-auto whitespace-nowrap font-mono text-xs text-slate-900 dark:text-slate-100">
                {command}
              </code>
              <CopyButton text={command} label="command" />
            </div>
          )}
          <p className="text-slate-600 dark:text-slate-400">
            Running the lab in Docker, or on another provider? Follow the{" "}
            <a
              href={DOCS_AI_SETUP_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={linkClassName}
            >
              AI assistant setup guide
            </a>
            .
          </p>
        </div>
      </div>
    </div>
  );
}
