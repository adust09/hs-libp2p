FROM node:22-bookworm-slim

WORKDIR /app
COPY interop/impl/js/package.json interop/impl/js/package-lock.json ./
RUN npm ci --omit=dev
COPY interop/impl/js/index.mjs ./

ENTRYPOINT ["node", "index.mjs"]
