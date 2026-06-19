FROM node:20-alpine AS builder

RUN npm install -g pnpm@9

WORKDIR /build
COPY package.json pnpm-workspace.yaml ./
COPY artifacts/nmapper/package.json ./artifacts/nmapper/
RUN pnpm install --frozen-lockfile 2>/dev/null || pnpm install

COPY artifacts/nmapper/ ./artifacts/nmapper/
WORKDIR /build/artifacts/nmapper
RUN pnpm run build

FROM nginx:stable-alpine

RUN chown -R nginx:nginx /usr/share/nginx/html \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/log/nginx \
    && chown -R nginx:nginx /etc/nginx/conf.d \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

COPY artifacts/nmapper/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/artifacts/nmapper/dist /usr/share/nginx/html

USER nginx
EXPOSE 8000
CMD ["nginx", "-g", "daemon off;"]
