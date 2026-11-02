# ─── Stage 1: Build & Compile ──────────────────────────────────────────
FROM node:22-slim AS builder

WORKDIR /build

RUN corepack enable && corepack prepare pnpm@latest --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json biome.json ./
COPY src/ ./src/
RUN pnpm run build
RUN pnpm prune --prod

# ─── Stage 2: Distroless Minimal Non-Root Runtime ──────────────────────
FROM gcr.io/distroless/nodejs20-debian12:nonroot AS runtime

LABEL maintainer="RitualDev Lab <team@ritualdev.com>"
LABEL org.opencontainers.image.title="DBShield"
LABEL org.opencontainers.image.description="Database Guardrail, Sandboxing Wire Proxy & PII Masking Engine"
LABEL org.opencontainers.image.source="https://github.com/RitualDev-Lab/DBShield"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=builder /build/package.json ./package.json
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules

EXPOSE 5433 9090 3100

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:9090/healthz').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"]

ENV NODE_ENV=production
ENV DBSHIELD_STORAGE_PATH=/tmp/dbshield.sqlite

USER nonroot:nonroot

ENTRYPOINT ["/nodejs/bin/node", "dist/cli.js"]
CMD ["proxy", "--port", "5433"]
