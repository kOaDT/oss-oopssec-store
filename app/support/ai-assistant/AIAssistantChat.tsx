"use client";

import { useState, useRef, useEffect } from "react";
import type { LlmErrorCode } from "@/lib/llm";
import ModelSetupPanel, { isSetupErrorCode } from "./ModelSetupPanel";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ChatError {
  message: string;
  code?: LlmErrorCode;
}

interface AIAssistantChatProps {
  model: string;
  endpointHost: string;
}

export default function AIAssistantChat({
  model,
  endpointHost,
}: AIAssistantChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ChatError | null>(null);
  const [mcpServerUrl, setMcpServerUrl] = useState("");
  const [showMcpSettings, setShowMcpSettings] = useState(false);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop =
        messagesContainerRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch("/api/ai-assistant", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: userMessage.content,
          ...(mcpServerUrl.trim() && { mcpServerUrl: mcpServerUrl.trim() }),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError({
          message: data.error || "Failed to get response",
          code: data.code,
        });
        return;
      }

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.response,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      setError({
        message: err instanceof Error ? err.message : "An error occurred",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="mx-auto flex h-[800px] max-w-3xl flex-col rounded-xl border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-800">
      <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
            <svg
              className="h-5 w-5 text-primary-600 dark:text-primary-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
              />
            </svg>
          </div>
          <div>
            <h2 className="font-semibold text-slate-900 dark:text-white">
              OSSBot
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              AI Customer Support Assistant
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowMcpSettings(!showMcpSettings)}
          className={`cursor-pointer rounded-lg px-3 py-1.5 text-sm transition-colors hover:bg-slate-100 dark:hover:bg-slate-700 ${
            mcpServerUrl.trim()
              ? "text-primary-600 dark:text-primary-400"
              : "text-slate-600 dark:text-slate-400"
          }`}
          title="MCP Server Settings"
        >
          <svg
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
            />
          </svg>
        </button>
      </div>

      {showMcpSettings && (
        <div className="border-b border-slate-200 px-6 py-3 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <label
              htmlFor="mcpServerUrl"
              className="shrink-0 text-xs font-medium text-slate-600 dark:text-slate-400"
            >
              MCP Server URL
            </label>
            <input
              type="text"
              id="mcpServerUrl"
              value={mcpServerUrl}
              onChange={(e) => setMcpServerUrl(e.target.value)}
              placeholder="https://your-mcp-server.example.com/mcp"
              className="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500/20 dark:border-slate-600 dark:bg-slate-700 dark:text-white dark:placeholder-slate-500"
            />
            {mcpServerUrl.trim() && (
              <button
                onClick={() => setMcpServerUrl("")}
                className="cursor-pointer text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
              >
                Clear
              </button>
            )}
          </div>
          <p className="mt-1.5 text-xs text-slate-400 dark:text-slate-500">
            Connect an external MCP server to extend OSSBot with custom tools.
          </p>
        </div>
      )}

      <div ref={messagesContainerRef} className="flex-1 overflow-y-auto p-4">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700">
              <svg
                className="h-8 w-8 text-slate-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                />
              </svg>
            </div>
            <h3 className="mb-2 font-medium text-slate-900 dark:text-white">
              Welcome to OSSBot!
            </h3>
            <p className="max-w-sm text-sm text-slate-500 dark:text-slate-400">
              I&apos;m here to help you with product inquiries, order status,
              returns, and general questions about OopsSec Store.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-2">
              {[
                "What products do you sell?",
                "How do I track my order?",
                "What's your return policy?",
              ].map((suggestion) => (
                <button
                  key={suggestion}
                  onClick={() => setInput(suggestion)}
                  className="cursor-pointer rounded-full border border-slate-200 px-3 py-1.5 text-sm text-slate-600 transition-colors hover:bg-slate-50 dark:border-slate-600 dark:text-slate-400 dark:hover:bg-slate-700"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[80%] rounded-2xl px-4 py-3 ${
                    message.role === "user"
                      ? "bg-primary-600 text-white"
                      : "bg-slate-100 text-slate-900 dark:bg-slate-700 dark:text-white"
                  }`}
                >
                  <p className="whitespace-pre-wrap text-sm">
                    {message.content}
                  </p>
                  <p
                    className={`mt-1 text-xs ${
                      message.role === "user"
                        ? "text-primary-200"
                        : "text-slate-400 dark:text-slate-500"
                    }`}
                  >
                    {message.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start">
                <div className="rounded-2xl bg-slate-100 px-4 py-3 dark:bg-slate-700">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-2 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.3s]"></div>
                    <div className="h-2 w-2 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.15s]"></div>
                    <div className="h-2 w-2 animate-bounce rounded-full bg-slate-400"></div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {error &&
        (isSetupErrorCode(error.code) ? (
          <ModelSetupPanel
            code={error.code}
            model={model}
            endpointHost={endpointHost}
          />
        ) : (
          <div
            role="alert"
            className="border-t border-red-200 bg-red-50 px-4 py-3 dark:border-red-900 dark:bg-red-900/20"
          >
            <p className="text-sm text-red-600 dark:text-red-400">
              {error.message}
            </p>
          </div>
        ))}

      <form
        onSubmit={handleSubmit}
        className="border-t border-slate-200 p-4 dark:border-slate-700"
      >
        <div className="flex gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your message..."
            disabled={isLoading}
            className="flex-1 rounded-xl border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/20 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-white dark:placeholder-slate-500"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="cursor-pointer flex items-center justify-center rounded-xl bg-primary-600 px-6 py-3 font-medium text-white transition-colors hover:bg-primary-700 focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
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
                d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
              />
            </svg>
          </button>
        </div>
      </form>
    </div>
  );
}
