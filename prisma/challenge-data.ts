import type { PrismaClient } from "../lib/generated/prisma/client";
import { CANARY_SLUGS, generateCanaryToken } from "../lib/sql-injection-canary";
import { flags, flagHints } from "./flags";

/**
 * Rows every install must carry, safe to re-apply on a database already in use:
 * no player progress hangs off them, and `found_flags` / `revealed_hints` point
 * at ids these upserts preserve.
 */
export const seedChallengeData = async (prisma: PrismaClient) => {
  for (const flag of flags) {
    await prisma.flag.upsert({
      where: { slug: flag.slug },
      update: {
        ...flag,
        // Prisma leaves `undefined` alone, so a badge dropped upstream would
        // outlive it here while a fresh install comes up without it.
        cve: flag.cve ?? null,
        cwe: flag.cwe ?? null,
        owasp: flag.owasp ?? null,
      },
      create: flag,
    });
  }

  console.log(`Ensured ${flags.length} flags`);

  // A flag dropped from the curriculum otherwise keeps its `found_flags` row
  // and holds the progress denominator up for good. The cascades take its
  // hints and their revealed rows with it.
  const removed = await prisma.flag.deleteMany({
    where: { slug: { notIn: flags.map((flag) => flag.slug) } },
  });

  if (removed.count > 0) {
    console.log(`Removed ${removed.count} flags no longer in the curriculum`);
  }

  for (const [slug, hints] of Object.entries(flagHints)) {
    const flag = await prisma.flag.findUnique({ where: { slug } });
    if (!flag) continue;

    for (let i = 0; i < hints.length; i++) {
      await prisma.hint.upsert({
        where: {
          flagId_level: { flagId: flag.id, level: i + 1 },
        },
        update: { content: hints[i] },
        create: { flagId: flag.id, level: i + 1, content: hints[i] },
      });
    }
  }

  console.log(`Ensured hints for ${Object.keys(flagHints).length} flags`);

  await seedCanaries(prisma);
};

/**
 * Tokens are left alone once minted: re-seeding is a routine recovery step, and
 * rotating them there would invalidate the payload a player is halfway through
 * building.
 */
export const seedCanaries = async (prisma: PrismaClient) => {
  await prisma.internalSecret.deleteMany({
    where: { slug: { notIn: [...CANARY_SLUGS] } },
  });

  for (const slug of CANARY_SLUGS) {
    await prisma.internalSecret.upsert({
      where: { slug },
      update: {},
      create: { slug, token: generateCanaryToken(slug) },
    });
  }

  console.log(`Ensured ${CANARY_SLUGS.length} SQL injection canaries`);
};
