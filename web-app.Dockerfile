FROM alpine

WORKDIR /data
RUN mkdir -p /data/web/public/

COPY ./web/public/default.css /data/web/public/
COPY ./web/public/network-side.png /data/web/public/
COPY ./web/public/index.html /data/web/public/index.html

COPY ./web/public/login.html /data/web/public/login.html
COPY ./web/public/demo_pods.html /data/web/public/demo_pods.html
COPY ./web/public/demo_namespace.html /data/web/public/demo_namespace.html

