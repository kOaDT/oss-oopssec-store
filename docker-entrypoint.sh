#!/bin/sh
set -e

DB_FILE="${DATABASE_URL#file:}"

if [ ! -f "$DB_FILE" ]; then
  echo "First run: initializing database..."
  npx prisma db push --skip-generate
  npx tsx prisma/seed.ts
  echo "Database initialized successfully."
else
  # A pulled image brings models and challenges the mounted volume never saw.
  # Replaying the whole seed would reset orders, so only the additive rows.
  echo "Existing database found: applying pending upgrades..."
  npm run db:upgrade
  echo "Database up to date."
fi

echo ""
echo "★ Enjoying the lab? A star helps others find it:"
echo "  https://github.com/kOaDT/oss-oopssec-store"
echo ""

# The published port reaches the container on its bridge IP, not on loopback.
exec npm run start:network
