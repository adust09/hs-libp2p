FROM node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb

WORKDIR /app
COPY interop/impl/js/package.json interop/impl/js/package-lock.json ./
RUN npm ci --omit=dev
COPY interop/impl/js/index.mjs ./

ENTRYPOINT ["node", "index.mjs"]
