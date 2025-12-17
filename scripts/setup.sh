#!/bin/bash

set -e

echo "Starting project setup..."

if [ ! -f .env ]; then
  echo "Creating .env file..."
  echo 'DATABASE_URL="file:./prisma/dev.db"' > .env
  echo ".env file created"
else
  echo ".env file already exists"
fi

echo "Installing dependencies..."
npm install

echo "Generating Prisma Client..."
npm run db:generate

echo "Pushing database schema..."
npm run db:push

echo "Seeding database..."
npm run db:seed

echo "Building project..."
npm run build

echo "Setup completed successfully!"
