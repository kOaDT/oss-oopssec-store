#!/bin/bash

set -e

echo ""
echo " ____ ____ ____ ____ ____ ____ _ "
echo " / __ \/ __// __/ / __ \ ___ ___ ___ / __/ ___ ____ / __/ / /_ ___ ____ ___ "
echo " / /_/ /\ \ _\ \ / /_/ // _ \ / _ \(_-<_\ \ / -_)/ __/_\ \ / __// _ \ / __// -_)"
echo " \____/___//___/ \____/ \___// .__/___/___/ \__/ \__//___/ \__/ \___//_/ \__/ "
echo " /_/ "
echo ""

echo "Starting project setup..."

if [ ! -f .env ]; then
 echo "Creating .env file..."
 PROJECT_ROOT=$(pwd)
 ENV_CONTENT="DATABASE_URL=\"file:${PROJECT_ROOT}/prisma/dev.db\""
 echo "$ENV_CONTENT" > .env || {
   echo "Error: Failed to write .env file" >&2
   exit 1
 }

 # Validate file exists and is non-empty
 if [ ! -s .env ]; then
   echo "Error: .env file is empty after creation" >&2
   exit 1
 fi

 # Basic syntax validation
 if ! grep -q '^DATABASE_URL=' .env; then
   echo "Error: .env file missing DATABASE_URL key" >&2
   exit 1
 fi

 echo ".env file created and validated"
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
npx prisma studio -b none &
PRISMA_PID=$!

npm start &
DEV_PID=$!

sleep 3
if command -v xdg-open > /dev/null; then
 xdg-open http://localhost:3000
elif command -v open > /dev/null; then
 open http://localhost:3000
fi

cleanup() {
 echo ""
 echo "Stopping Prisma Studio and application..."
 kill $PRISMA_PID 2>/dev/null || true
 kill $DEV_PID 2>/dev/null || true
 exit 0
}

trap cleanup SIGINT SIGTERM

echo "Prisma Studio and application are running..."
echo "Prisma Studio: http://localhost:5555"
echo "Application: http://localhost:3000 (opened in browser)"
echo "Press Ctrl+C to stop both processes."

wait