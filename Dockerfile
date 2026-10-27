# syntax=docker/dockerfile:1

# Keep this default in sync with .nvmrc; tests/unit/node-version-parity.test.ts
# fails the build if they drift.
ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
# Cypress runs on the host against the container, never inside it: skip the
# binary its postinstall would otherwise download.
RUN CYPRESS_INSTALL_BINARY=0 npm ci && npm cache clean --force

# The published image builds from a Git context, which BuildKit never filters
# through .dockerignore: these exclusions decide what ships.
COPY --exclude=docs --exclude=tests --exclude=cypress --exclude=.cursor \
  --exclude=.husky --exclude=packages/create-oss-store . .
# The app imports the curriculum to title discussion threads the way the
# walkthroughs do. Keep it free of imports: nothing else under docs/ ships, so
# a dependency it grows would break the Docker build and only the Docker build.
COPY docs/src/data/roadmap.ts docs/src/data/roadmap.ts

# Prisma v6 requires DATABASE_URL even during generate; use a throwaway value
RUN DATABASE_URL=file:/tmp/build.db npx prisma generate

# Provide a temporary database so Next.js can complete the build
# (server components may query the DB during static analysis)
RUN DATABASE_URL=file:/tmp/build.db npx prisma db push --skip-generate

ENV NEXT_TELEMETRY_DISABLED=1
RUN DATABASE_URL=file:/tmp/build.db npm run build

# The entrypoint seeds through tsx, and both the seed and the Prisma config
# load dotenv: they are runtime dependencies, so the prune must keep them.
RUN npm prune --omit=dev \
  && rm -rf .next/cache /tmp/build.db \
  && chmod +x docker-entrypoint.sh

FROM node:${NODE_VERSION}-alpine

WORKDIR /app

COPY --from=builder /app /app

RUN mkdir -p /app/data /app/uploads /app/documents/invoices /app/logs

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATABASE_URL=file:/app/data/dev.db
ENV PARTNER_SIGNING_KEY_PATH=/app/data/partner-signing-key.pem
ENV NEXT_PUBLIC_BASE_URL=http://localhost:3000

EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
