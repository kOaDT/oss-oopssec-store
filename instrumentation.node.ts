import fs from "fs";
import path from "path";

const logsDir = path.join(process.cwd(), "logs");

if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const logFile = path.join(logsDir, "app.log");

const originalLog = console.log;
const originalWarn = console.warn;
const originalError = console.error;
const originalInfo = console.info;

function appendLog(level: string, args: unknown[]) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message: args
      .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
      .join(" "),
  });

  try {
    fs.appendFileSync(logFile, entry + "\n");
  } catch {
    // Silently ignore write errors
  }
}

console.log = (...args: unknown[]) => {
  appendLog("log", args);
  originalLog.apply(console, args);
};

console.warn = (...args: unknown[]) => {
  appendLog("warn", args);
  originalWarn.apply(console, args);
};

console.error = (...args: unknown[]) => {
  appendLog("error", args);
  originalError.apply(console, args);
};

console.info = (...args: unknown[]) => {
  appendLog("info", args);
  originalInfo.apply(console, args);
};
