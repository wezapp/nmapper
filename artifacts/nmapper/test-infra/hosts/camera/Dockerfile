FROM alpine:3.19

RUN apk add --no-cache nginx socat bash

RUN mkdir -p /var/www/html /run/nginx

COPY index.html /var/www/html/index.html
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 554 8080 8554

CMD ["/start.sh"]
