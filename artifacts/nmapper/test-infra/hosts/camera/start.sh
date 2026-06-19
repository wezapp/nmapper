#!/bin/sh

BRAND=${CAMERA_BRAND:-Hikvision}
MODEL=${CAMERA_MODEL:-Unknown}

# Inject brand info in the HTML
sed -i "s/>IP Camera - Login/<\/title><title>${BRAND} ${MODEL} - Login/" /var/www/html/index.html
sed -i "s/>IP Camera</${BRAND}</" /var/www/html/index.html
sed -i "s/id=\"model\"><\/p>/id=\"model\">${MODEL}<\/p>/" /var/www/html/index.html

# Inject brand in Server header
sed -i "s/server_name _;/server_name _;\n    add_header Server \"${BRAND}-Webs\";/" /etc/nginx/http.d/default.conf

nginx &

# Simulate RTSP on 554 and 8554
# Returns a minimal valid RTSP response to OPTIONS
rtsp_response() {
    printf "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\nServer: ${BRAND} RTSP Server\r\n\r\n"
}

while true; do
    socat TCP4-LISTEN:554,reuseaddr EXEC:'sh -c "read l; printf \"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n\""' 2>/dev/null || true
done &

while true; do
    socat TCP4-LISTEN:8554,reuseaddr EXEC:'sh -c "read l; printf \"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n\""' 2>/dev/null || true
done &

echo "Camera [${BRAND} ${MODEL}] started — HTTP:80/8080, RTSP:554/8554"
wait
