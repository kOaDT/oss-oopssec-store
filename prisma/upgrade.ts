import { prisma } from "./seed-client";
import { seedChallengeData } from "./challenge-data";

/**
 * Brings an existing database up to date without replaying the full seed, which
 * recreates orders and supplier orders and would reset player progress.
 */
async function main() {
  console.log("Upgrading database...");

  // `db push` creates the tables, so a schema-complete but unseeded database
  // would upgrade cleanly and serve a store with no catalogue at all.
  const initialized = await prisma.projectInit.findFirst();
  if (!initialized) {
    throw new Error(
      [
        "Database not initialized: no row in project_init, so the catalogue, users and orders were never seeded.",
        "An upgrade only replays challenge rows, which would leave an empty store.",
        "",
        "Seed it first, it is idempotent and keeps whatever is already there:",
        "  npm run db:seed                                           (npm)",
        "  docker compose run --rm --entrypoint npm app run db:seed  (Docker)",
        "",
      ].join("\n")
    );
  }

  await seedChallengeData(prisma);
  console.log("Upgrade completed!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
