# Build stage: the full Node image carries python/make/g++ so
# better-sqlite3 can build from source if no prebuilt binary matches
# the target platform.
FROM node:20-bookworm AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Runtime: slim image, non-root user, dedicated data directory.
FROM node:20-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY server.js ./
COPY src ./src
COPY providers.json ./providers.json

RUN mkdir -p /data && chown -R node:node /app /data

USER node
EXPOSE 4000

CMD ["node", "server.js"]
