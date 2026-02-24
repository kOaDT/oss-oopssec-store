#!/bin/sh
set -e

DB_FILE="${DATABASE_URL#file:}"

if [ ! -f "$DB_FILE" ]; then
  echo "First run: initializing database..."
  npx prisma db push --skip-generate
  npx tsx prisma/seed.ts
  echo "Database initialized successfully."
fi

exec npm start
