# ─── Stage 1: Build & Compile ──────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /build

# Enable Corepack and pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy dependency manifests
COPY package.json pnpm-lock.yaml ./

# Install all dependencies (including devDependencies for build)
RUN pnpm install --frozen-lockfile

# Copy source code and configuration files
COPY tsconfig.json biome.json ./
COPY src/ ./src/

# Compile TypeScript to dist/
RUN pnpm run build

# Prune devDependencies to keep only production packages
RUN pnpm prune --prod

# ─── Stage 2: Minimal Distroless/Hardened Runtime ─────────────────────
FROM node:22-alpine AS runtime

LABEL maintainer="RitualDev Lab <team@ritualdev.com>"
LABEL org.opencontainers.image.title="DBShield"
LABEL org.opencontainers.image.description="AI Database Guardrail & Wire Proxy with Native Prometheus Metrics"
LABEL org.opencontainers.image.source="https://github.com/RitualDev-Lab/DBShield"
LABEL org.opencontainers.image.licenses="MIT"

# Install curl for container HEALTHCHECK probe
RUN apk add --no-cache curl

WORKDIR /app

# Create unprivileged system user and group (UID 10001, GID 10001)
RUN addgroup -g 10001 -S dbshield && \
    adduser -u 10001 -S dbshield -G dbshield

# Copy built distribution, production dependencies, and package.json
COPY --from=builder --chown=dbshield:dbshield /build/package.json ./package.json
COPY --from=builder --chown=dbshield:dbshield /build/dist ./dist
COPY --from=builder --chown=dbshield:dbshield /build/node_modules ./node_modules

# Ensure state directory is writable for SQLite or audit logs
RUN mkdir -p /app/data && chown -R dbshield:dbshield /app/data

# Environment configuration defaults
ENV NODE_ENV=production \
    DBSHIELD_PROXY_HOST=0.0.0.0 \
    DBSHIELD_PROXY_PORT=5433 \
    DBSHIELD_METRICS_HOST=0.0.0.0 \
    DBSHIELD_METRICS_PORT=9090 \
    DBSHIELD_ENABLE_METRICS=true \
    DBSHIELD_STORAGE_PATH=/app/data/dbshield.sqlite

# Switch to non-root unprivileged user
USER 10001:10001

# Expose Proxy Port (5433) and Prometheus / Health Port (9090)
EXPOSE 5433 9090

# Container liveness & healthcheck probe
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["proxy", "--port", "5433", "--metrics-port", "9090", "--metrics-host", "0.0.0.0"]
