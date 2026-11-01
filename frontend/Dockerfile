FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
# Alpine v3.24 security fixes: CVE-2026-77214 and CVE-2026-88806.
# Fetch exact signed packages separately; the final install is offline with the base trusted keys.
FROM nginxinc/nginx-unprivileged:1.30.5-alpine3.24@sha256:56b8272e43a0525f67aed68d1e0794a712d10e3e45a563e118e9a77c817e6f86 AS frontend-security-packages
USER 0
RUN set -eu; mkdir /packages; arch="$(apk --print-arch)"; \
    case "$arch" in \
      x86_64) expat=32b127f31e0a919110a18a7f0bb3780d8fb66ba4d8d61b2d301d633f0e319d0e; x11=016efc189c6d566061ffe206ed0780e32686c1a8c832a3917d35d2c66d61a40f ;; \
      aarch64) expat=7128bfe18b8a315b9cf90ddf0beffeee454648ae72ff7898ff7d7b09803a559d; x11=d460c111c1fc40e8f84367907b3e50a58a2b19c3e9d54f7c1f0e4aea7a376e3b ;; \
      *) exit 1 ;; \
    esac; \
    wget -O /packages/libexpat.apk https://dl-cdn.alpinelinux.org/alpine/v3.24/main/$arch/libexpat-2.9.0-r0.apk; \
    wget -O /packages/libx11.apk https://dl-cdn.alpinelinux.org/alpine/v3.24/main/$arch/libx11-1.8.14-r0.apk; \
    printf '%s\n' "$expat  /packages/libexpat.apk" "$x11  /packages/libx11.apk" | sha256sum -c -

FROM nginxinc/nginx-unprivileged:1.30.5-alpine3.24@sha256:56b8272e43a0525f67aed68d1e0794a712d10e3e45a563e118e9a77c817e6f86
USER 0
RUN --mount=type=bind,from=frontend-security-packages,source=/packages,target=/packages,ro \
    apk add --no-network /packages/libexpat.apk /packages/libx11.apk \
    && apk info -e 'libexpat=2.9.0-r0' 'libx11=1.8.14-r0' \
    && ldd /usr/lib/libexpat.so.1 && ldd /usr/lib/libX11.so.6
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
USER 101
CMD ["nginx", "-g", "daemon off;"]
