#!/bin/bash

set -e

echo "Starting project setup..."

if [ ! -f .env ]; then
  echo "Creating .env file..."
  PROJECT_ROOT=$(pwd)
  echo "DATABASE_URL=\"file:${PROJECT_ROOT}/prisma/dev.db\"" > .env
  echo ".env file created"
else
  echo ".env file already exists"
fi

echo "Installing dependencies..."
npm install

echo "Generating Prisma Client..."
npm run db:generate

if [ -f prisma/dev.db ]; then
  echo "Removing existing database file..."
  rm prisma/dev.db
  echo "Existing database file removed"
fi

echo "Pushing database schema..."
npm run db:push

echo "Seeding database..."
npm run db:seed

echo "Building project..."
npm run build

echo "Setup completed successfully!"

echo "Launching Prisma Studio and application..."
npm run db:studio &
PRISMA_PID=$!

npm run dev &
DEV_PID=$!

cleanup() {
  echo ""
  echo "Stopping Prisma Studio and application..."
  kill $PRISMA_PID 2>/dev/null || true
  kill $DEV_PID 2>/dev/null || true
  exit 0
}

trap cleanup SIGINT SIGTERM

echo "Prisma Studio and application are running..."
echo "Prisma Studio PID: $PRISMA_PID"
echo "Dev server PID: $DEV_PID"
echo "Press Ctrl+C to stop both processes."

wait