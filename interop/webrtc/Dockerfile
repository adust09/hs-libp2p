FROM node:22-bookworm-slim

WORKDIR /app
COPY interop/webrtc/package.json interop/webrtc/package-lock.json ./
RUN npm ci --omit=dev
COPY interop/webrtc/index.mjs ./

ENTRYPOINT ["node", "index.mjs"]
