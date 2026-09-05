import { spawn } from "child_process";

// A failing `next build` can emit megabytes before it dies, and only the tail
// carries the error. Keep a bounded window of each stream instead of growing
// one string until the command is done.
const MAX_STREAM_CHARS = 64 * 1024;
const TRUNCATION_NOTICE = "[... earlier output truncated ...]\n";

function appendCapped(buffer, chunk) {
  const next = buffer + chunk;
  if (next.length <= MAX_STREAM_CHARS) {
    return next;
  }
  return TRUNCATION_NOTICE + next.slice(-MAX_STREAM_CHARS);
}

export function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: "pipe",
      shell: process.platform === "win32",
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout = appendCapped(stdout, data.toString());
    });

    child.stderr.on("data", (data) => {
      stderr = appendCapped(stderr, data.toString());
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        // Tools routinely write an unrelated notice to stderr — the Browserslist
        // "caniuse-lite is outdated" advisory during `next build`, Prisma's
        // warnings during `db:generate` — while the actual compilation error
        // goes to stdout. Picking one stream over the other would hide it, so
        // report both and let the user read the whole failure.
        const output = [stderr.trim(), stdout.trim()]
          .filter(Boolean)
          .join("\n");
        reject(new Error(output || `Command failed with code ${code}`));
      }
    });

    child.on("error", (error) => {
      reject(error);
    });
  });
}
