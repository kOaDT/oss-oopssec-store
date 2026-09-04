#!/usr/bin/env node

import { createOssStore } from "../src/index.js";

const USAGE = `Usage: create-oss-store [project-name] [options]

Options:
  --ref <git-ref>  Tag or branch to install
                   (default: the release tag matching this CLI version)
  -h, --help       Show this message`;

const GIT_REF = /^[\w.-]+(?:\/[\w.-]+)*$/;

function parseArgs(argv) {
  let projectName;
  let ref;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === "-h" || arg === "--help") {
      return { help: true };
    }

    if (arg === "--ref" || arg.startsWith("--ref=")) {
      const value = arg === "--ref" ? argv[++i] : arg.slice("--ref=".length);
      if (!value || value.startsWith("-")) {
        throw new Error("Option --ref requires a git ref.");
      }
      if (!GIT_REF.test(value) || value.includes("..")) {
        throw new Error(`Invalid git ref: ${value}`);
      }
      ref = value;
      continue;
    }

    if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    }
    if (projectName !== undefined) {
      throw new Error(`Unexpected argument: ${arg}`);
    }
    projectName = arg;
  }

  return { projectName, ref };
}

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  console.error();
  console.error(USAGE);
  process.exit(1);
}

if (args.help) {
  console.log(USAGE);
} else {
  await createOssStore(args.projectName, { ref: args.ref });
}
