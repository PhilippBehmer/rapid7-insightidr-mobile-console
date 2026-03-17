FROM node:20-bookworm-slim AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM node:20-bookworm-slim AS backend-deps

WORKDIR /app/backend

COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev

FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PORT=3000

RUN groupadd --system pocketsoc \
    && useradd --system --gid pocketsoc --home-dir /app --create-home pocketsoc

WORKDIR /app/backend

COPY backend/package.json backend/package-lock.json ./
COPY backend/server.js ./
COPY --from=backend-deps /app/backend/node_modules ./node_modules

WORKDIR /app

COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

RUN mkdir -p /app/data \
    && chown -R pocketsoc:pocketsoc /app

WORKDIR /app/backend

USER pocketsoc

EXPOSE 3000

CMD ["node", "server.js"]
