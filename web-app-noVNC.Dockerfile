FROM alpine

WORKDIR /data
RUN mkdir -p /data/web/public/noVNC/

COPY ./web/public/default.css /data/web/public/
COPY ./web/public/network-side.png /data/web/public/
COPY ./web/public/demo_novnc.html /data/web/public/index.html

COPY ./web/public/login.html /data/web/public/login.html

COPY ./web/public/noVNC/app /data/web/public/noVNC/app
COPY ./web/public/noVNC/core /data/web/public/noVNC/core
COPY ./web/public/noVNC/vendor /data/web/public/noVNC/vendor
COPY ./web/public/noVNC/*.html /data/web/public/noVNC/
