import { writeFileSync, existsSync, readFileSync, rmSync } from "fs";
import { homedir } from "os";
import { resolve, join } from "path";
import chalk from "chalk";
import ora from "ora";
import degit from "degit";
import { runCommand } from "./run-command.js";

const REPO = "kOaDT/oss-oopssec-store";
const FALLBACK_REF = "main";
const DEGIT_CACHE = join(homedir(), ".degit", "github", ...REPO.split("/"));

const ASCII_ART = [
  String.raw`   ____  ____ ____     ____                  ____            ____  _                  `,
  String.raw`  / __ \/ __// __/    / __ \ ___   ___  ___ / __/ ___  ____ / __/ / /_ ___   ____ ___ `,
  String.raw` / /_/ /\ \ _\ \     / /_/ // _ \ / _ \(_-<_\ \  / -_)/ __/_\ \  / __// _ \ / __// -_)`,
  String.raw` \____/___//___/     \____/ \___// .__/___/___/  \__/ \__//___/  \__/ \___//_/   \__/ `,
  String.raw`                                /_/                                                   `,
];

export async function createOssStore(projectName, { ref } = {}) {
  console.log();
  ASCII_ART.forEach((line) => console.log(chalk.cyan(line)));
  console.log();

  if (!projectName) {
    projectName = "oss-oopssec-store";
    console.log(
      chalk.yellow(`No project name provided, using "${projectName}"`)
    );
    console.log();
  }

  const targetPath = resolve(process.cwd(), projectName);

  if (existsSync(targetPath)) {
    console.log(chalk.red(`Error: Directory "${projectName}" already exists.`));
    process.exit(1);
  }

  await cloneRepository(targetPath, ref);

  // Create .env file
  const envSpinner = ora("Creating .env file...").start();
  try {
    const envPath = join(targetPath, ".env");
    const dbPath = join(targetPath, "prisma", "dev.db");
    writeFileSync(envPath, `DATABASE_URL="file:${dbPath}"\n`);
    envSpinner.succeed(".env file created");
  } catch (error) {
    envSpinner.fail("Failed to create .env file");
    failAndCleanup(error, targetPath);
  }

  // Install dependencies
  const installSpinner = ora("Installing dependencies...").start();
  try {
    await runCommand("npm", ["install"], targetPath);
    installSpinner.succeed("Dependencies installed");
  } catch (error) {
    installSpinner.fail("Failed to install dependencies");
    failAndCleanup(error, targetPath);
  }

  // Generate Prisma client
  const prismaSpinner = ora("Generating Prisma client...").start();
  try {
    await runCommand("npm", ["run", "db:generate"], targetPath);
    prismaSpinner.succeed("Prisma client generated");
  } catch (error) {
    prismaSpinner.fail("Failed to generate Prisma client");
    failAndCleanup(error, targetPath);
  }

  // Push database schema
  const dbSpinner = ora("Setting up database...").start();
  try {
    await runCommand("npm", ["run", "db:push"], targetPath);
    dbSpinner.succeed("Database schema pushed");
  } catch (error) {
    dbSpinner.fail("Failed to push database schema");
    failAndCleanup(error, targetPath);
  }

  // Seed database
  const seedSpinner = ora("Seeding database with CTF flags...").start();
  try {
    await runCommand("npm", ["run", "db:seed"], targetPath);
    seedSpinner.succeed("Database seeded");
  } catch (error) {
    seedSpinner.fail("Failed to seed database");
    failAndCleanup(error, targetPath);
  }

  // Build
  const buildSpinner = ora("Building lab...").start();
  try {
    await runCommand("npm", ["run", "build"], targetPath);
    buildSpinner.succeed("Lab is operational");
  } catch (error) {
    buildSpinner.fail("Failed to build lab");
    failAndCleanup(error, targetPath);
  }

  // Success message
  console.log();
  console.log(chalk.green.bold("Setup complete!"));
  console.log();
  console.log("To start hunting for flags:");
  console.log();
  console.log(chalk.cyan(`  cd ${projectName}`));
  console.log(chalk.cyan("  npm start"));
  console.log();
  console.log(
    `Then open ${chalk.underline("http://localhost:3000")} in your browser.`
  );
  console.log();
  console.log(chalk.dim("Good luck finding all the flags!"));
  console.log();
  console.log(
    `${chalk.yellow("★")} Enjoying the lab? A star helps others find it: ${chalk.underline("https://github.com/kOaDT/oss-oopssec-store")}`
  );
  console.log();
}

/**
 * Installs the release matching this CLI version so that a given
 * `npx create-oss-store@x.y.z` always produces the same lab. An explicit ref is
 * honoured as-is; the default tag falls back to the default branch when the
 * release does not exist, which is the case for an unpublished CLI.
 */
async function cloneRepository(targetPath, requestedRef) {
  const ref = requestedRef ?? `v${readCliVersion()}`;

  const cloneSpinner = ora(`Cloning repository (${ref})...`).start();
  try {
    await clone(ref, targetPath);
    cloneSpinner.succeed(`Repository cloned (${ref})`);
    return;
  } catch (error) {
    if (requestedRef || error.code !== "MISSING_REF") {
      cloneSpinner.fail("Failed to clone repository");
      failAndCleanup(error, targetPath);
    }
    cloneSpinner.warn(
      chalk.yellow(
        `Release ${ref} not found, falling back to "${FALLBACK_REF}". The lab may not match this CLI version.`
      )
    );
  }

  const fallbackSpinner = ora(
    `Cloning repository (${FALLBACK_REF})...`
  ).start();
  try {
    await clone(FALLBACK_REF, targetPath);
    fallbackSpinner.succeed(`Repository cloned (${FALLBACK_REF})`);
  } catch (error) {
    fallbackSpinner.fail("Failed to clone repository");
    failAndCleanup(error, targetPath);
  }
}

async function clone(ref, targetPath) {
  // degit reuses whatever sits at its cache path without validating it, so an
  // interrupted download leaves a truncated tarball that fails every later run
  // with "zlib: unexpected end of file". Always start from a clean cache.
  rmSync(DEGIT_CACHE, { recursive: true, force: true });

  const emitter = degit(`${REPO}#${ref}`, { cache: false, force: true });
  // degit swallows a failing `git ls-remote` and reports the ref as missing,
  // which would make an unreachable GitHub look like a deleted release and send
  // the user chasing a phantom tag. The warning it emits on the way is the only
  // way to tell the two apart.
  let unreachable = null;
  emitter.on("warn", (info) => {
    if (info.code === "COULD_NOT_FETCH") {
      unreachable = info;
    }
  });

  try {
    await emitter.clone(targetPath);
  } catch (error) {
    rmSync(DEGIT_CACHE, { recursive: true, force: true });
    if (unreachable && error.code === "MISSING_REF") {
      throw Object.assign(
        new Error(
          `Could not reach ${unreachable.url}. Check your network connection and proxy settings, and make sure "git" is installed.`
        ),
        { code: "COULD_NOT_FETCH" }
      );
    }
    throw error;
  }
}

function readCliVersion() {
  const packageJson = readFileSync(
    new URL("../package.json", import.meta.url),
    "utf8"
  );
  return JSON.parse(packageJson).version;
}

function failAndCleanup(error, targetPath) {
  console.error(chalk.red(error.message));
  try {
    // rmSync can throw on Windows (EBUSY/EPERM) if a file in node_modules
    // is locked by antivirus or an editor. Catch it so we exit cleanly
    // instead of crashing mid-cleanup and leaving a broken project behind.
    rmSync(targetPath, {
      recursive: true,
      force: true,
      maxRetries: 3,
      retryDelay: 200,
    });
  } catch {
    console.error(
      chalk.yellow(`Could not remove ${targetPath}, please delete it manually.`)
    );
  }
  process.exit(1);
}
