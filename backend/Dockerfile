FROM aquasec/trivy:latest AS trivy

FROM node:22-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production \
    DOCKSAFE_PORT=5000 \
    TRIVY_PATH=/usr/local/bin/trivy \
    TRIVY_IMAGE_SOURCE=remote \
    TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:' + (process.env.DOCKSAFE_PORT || 5000) + '/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["npm", "start"]
