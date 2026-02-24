FROM node:20-alpine

RUN apk add --no-cache python3 make g++ gcc libxml2-dev libxslt-dev

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Prisma v6 requires DATABASE_URL even during generate; use a throwaway value
RUN DATABASE_URL=file:/tmp/build.db npx prisma generate

# Provide a temporary database so Next.js can complete the build
# (server components may query the DB during static analysis)
RUN DATABASE_URL=file:/tmp/build.db npx prisma db push --skip-generate

ENV NEXT_TELEMETRY_DISABLED=1
RUN DATABASE_URL=file:/tmp/build.db npm run build

RUN rm -f /tmp/build.db

RUN mkdir -p /app/data /app/uploads /app/documents/invoices /app/logs

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATABASE_URL=file:/app/data/dev.db
ENV NEXT_PUBLIC_BASE_URL=http://localhost:3000

RUN chmod +x ./docker-entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
