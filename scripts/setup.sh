#!/bin/bash

set -e

echo ""
echo "   ____  ____ ____     ____                  ____            ____  _                  "
echo "  / __ \/ __// __/    / __ \ ___   ___  ___ / __/ ___  ____ / __/ / /_ ___   ____ ___ "
echo " / /_/ /\ \ _\ \     / /_/ // _ \ / _ \(_-<_\ \  / -_)/ __/_\ \  / __// _ \ / __// -_)"
echo " \____/___//___/     \____/ \___// .__/___/___/  \__/ \__//___/  \__/ \___//_/   \__/ "
echo "                                /_/                                                   "
echo ""

# npm only warns about engines.node, so refuse an older Node here, before
# anything is installed or the existing database is removed.
REQUIRED_NODE_MAJOR=$(sed -n 's/.*"node": *">=\([0-9]*\).*/\1/p' package.json | head -n 1)
NODE_VERSION=$(node --version)
NODE_MAJOR=$(echo "$NODE_VERSION" | sed 's/^v\([0-9]*\).*/\1/')
if [ "$NODE_MAJOR" -lt "$REQUIRED_NODE_MAJOR" ]; then
  echo "OopsSec Store needs Node.js ${REQUIRED_NODE_MAJOR} or newer, but this is ${NODE_VERSION}." >&2
  echo "Install it with \"nvm install ${REQUIRED_NODE_MAJOR} && nvm use ${REQUIRED_NODE_MAJOR}\", or from https://nodejs.org, then run npm run setup again." >&2
  exit 1
fi

echo "Starting project setup..."

if [ ! -f .env ]; then
  echo "Creating .env file..."
  PROJECT_ROOT=$(pwd)
  echo "DATABASE_URL=\"file:${PROJECT_ROOT}/prisma/dev.db\"" > .env
  echo "PARTNER_SIGNING_KEY_PATH=\"${PROJECT_ROOT}/prisma/partner-signing-key.pem\"" >> .env
  cat >> .env <<'EOF'
# AI assistant: a local Ollama model by default. Set these to use another
# OpenAI-compatible endpoint: https://koadt.github.io/oss-oopssec-store/ai-setup
# LLM_BASE_URL="http://localhost:11434/v1"
# LLM_MODEL="gemma4:e4b"
# LLM_API_KEY=""
EOF
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

echo ""
echo "★ Enjoying the lab? A star helps others find it:"
echo "  https://github.com/kOaDT/oss-oopssec-store"
echo ""

echo "Launching Prisma Studio and application..."
npx prisma studio -b none --hostname 127.0.0.1 --port 5555 &
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
echo "Application:   http://localhost:3000 (opened in browser)"
echo "Press Ctrl+C to stop both processes."

wait