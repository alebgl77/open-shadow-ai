FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
# Nginx 1.30.6 fixes the HTTP parser advisories; Alpine musl fixes CVE-2026-107891.
# Fetch exact signed packages separately; the final install is offline with the base trusted keys.
FROM nginxinc/nginx-unprivileged:1.30.6-alpine3.24-slim@sha256:5d8bb9437d74a600ec5dbf90c035451c724dc33eac8d3a71078f6f8612c345f6 AS frontend-security-packages
USER 0
RUN set -eu; mkdir /packages; arch="$(apk --print-arch)"; \
    case "$arch" in \
      x86_64) musl=e142255d0fa397f14318996bc10378093dcc069dc3dd1b6818c8f28a789c21da; utils=47263d05842c5e12d01e0369e5b5bea51733323501c00ca21968a5102de137ca ;; \
      aarch64) musl=2e17864102278d9049c3a56f1bceed9e8cf287065617e579325123443daed8a5; utils=bb460bdc009e88989bd5adca8a7c8298c339cba99da11c6196c818e042fbaf49 ;; \
      *) exit 1 ;; \
    esac; \
    wget -O /packages/musl.apk https://dl-cdn.alpinelinux.org/alpine/v3.24/main/$arch/musl-1.2.6-r3.apk; \
    wget -O /packages/musl-utils.apk https://dl-cdn.alpinelinux.org/alpine/v3.24/main/$arch/musl-utils-1.2.6-r3.apk; \
    printf '%s\n' "$musl  /packages/musl.apk" "$utils  /packages/musl-utils.apk" | sha256sum -c -

FROM nginxinc/nginx-unprivileged:1.30.6-alpine3.24-slim@sha256:5d8bb9437d74a600ec5dbf90c035451c724dc33eac8d3a71078f6f8612c345f6
USER 0
RUN --mount=type=bind,from=frontend-security-packages,source=/packages,target=/packages,ro \
    apk add --no-network /packages/musl.apk /packages/musl-utils.apk \
    && apk info -e 'musl=1.2.6-r3' 'musl-utils=1.2.6-r3' \
    && ldd /usr/sbin/nginx && nginx -v
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
USER 101
CMD ["nginx", "-g", "daemon off;"]
