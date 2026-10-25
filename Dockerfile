# ========================================================
# JOIF Cloud - Central SSH Account Portal (Multi-Arch)
# Compatible con ARM64 (Oracle Cloud Ampere A1) y AMD64
# ========================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Instalar dependencias necesarias para compilar módulos nativos si se requieren
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

FROM node:20-alpine AS runner

WORKDIR /app

# Dependencias mínimas de ejecución y curl/wget para healthcheck
RUN apk add --no-cache tzdata wget \
    && cp /usr/share/zoneinfo/America/Argentina/Buenos_Aires /etc/localtime \
    && echo "America/Argentina/Buenos_Aires" > /etc/timezone \
    && apk del tzdata

# Crear directorio persistente para SQLite
RUN mkdir -p /app/data && chown -R node:node /app

COPY --from=builder /app/node_modules ./node_modules
COPY --chown=node:node . .

USER node

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_PATH=/app/data/portal.sqlite

EXPOSE 3000

# Verificación de salud integrada para Portainer y Docker
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

CMD ["node", "server.js"]
