import { spawn } from "child_process";
import { writeFileSync, existsSync } from "fs";
import { resolve, join } from "path";
import chalk from "chalk";
import ora from "ora";
import degit from "degit";

const REPO = "kOaDT/oss-oopssec-store";

export async function createOssStore(projectName) {
  console.log();
  console.log(chalk.bold("OSS – OopsSec Store"));
  console.log(chalk.dim("Vulnerable Web Application for Security Training"));
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

  // Clone repository
  const cloneSpinner = ora("Cloning repository...").start();
  try {
    const emitter = degit(REPO, { cache: false, force: true });
    await emitter.clone(targetPath);
    cloneSpinner.succeed("Repository cloned");
  } catch (error) {
    cloneSpinner.fail("Failed to clone repository");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Create .env file
  const envSpinner = ora("Creating .env file...").start();
  try {
    const envPath = join(targetPath, ".env");
    const dbPath = join(targetPath, "prisma", "dev.db");
    writeFileSync(envPath, `DATABASE_URL="file:${dbPath}"\n`);
    envSpinner.succeed(".env file created");
  } catch (error) {
    envSpinner.fail("Failed to create .env file");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Install dependencies
  const installSpinner = ora("Installing dependencies...").start();
  try {
    await runCommand("npm", ["install"], targetPath);
    installSpinner.succeed("Dependencies installed");
  } catch (error) {
    installSpinner.fail("Failed to install dependencies");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Generate Prisma client
  const prismaSpinner = ora("Generating Prisma client...").start();
  try {
    await runCommand("npm", ["run", "db:generate"], targetPath);
    prismaSpinner.succeed("Prisma client generated");
  } catch (error) {
    prismaSpinner.fail("Failed to generate Prisma client");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Push database schema
  const dbSpinner = ora("Setting up database...").start();
  try {
    await runCommand("npm", ["run", "db:push"], targetPath);
    dbSpinner.succeed("Database schema pushed");
  } catch (error) {
    dbSpinner.fail("Failed to push database schema");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Seed database
  const seedSpinner = ora("Seeding database with CTF flags...").start();
  try {
    await runCommand("npm", ["run", "db:seed"], targetPath);
    seedSpinner.succeed("Database seeded");
  } catch (error) {
    seedSpinner.fail("Failed to seed database");
    console.error(chalk.red(error.message));
    process.exit(1);
  }

  // Success message
  console.log();
  console.log(chalk.green.bold("Setup complete!"));
  console.log();
  console.log("To start hunting for flags:");
  console.log();
  console.log(chalk.cyan(`  cd ${projectName}`));
  console.log(chalk.cyan("  npm run dev"));
  console.log();
  console.log(
    `Then open ${chalk.underline("http://localhost:3000")} in your browser.`
  );
  console.log();
  console.log(chalk.dim("Good luck finding all the flags!"));
  console.log();
}

function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: "pipe",
      shell: process.platform === "win32",
    });

    let stderr = "";

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(stderr || `Command failed with code ${code}`));
      }
    });

    child.on("error", (error) => {
      reject(error);
    });
  });
}
