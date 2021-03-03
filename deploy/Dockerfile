# build stage
FROM quay.io/fedora/fedora:34-x86_64 AS build
WORKDIR /app
RUN sudo dnf install -y git golang

RUN git clone https://github.com/yaacov/oc-proxy.git /app \
  && git clone https://github.com/novnc/noVNC /app/web/public/noVNC \
  && go get github.com/yaacov/oc-proxy/cmd/oc-proxy \
  && CGO_ENABLED=0 GOOS=linux go build -o /app/ /app/cmd/oc-proxy/

# deploy stage

# quay does not have an alpine image, if you don't want to use dockerhub
# an option is to switch to using fedora-minimal:
# FROM quay.io/fedora/fedora-minimal:34-x86_64
FROM alpine

WORKDIR /app
RUN mkdir -p /app/wep/public/noVNC/

COPY --from=build /app/oc-proxy /app/

COPY --from=build /app/web/public/default.css /app/web/public/
COPY --from=build /app/web/public/*.html /app/web/public/

COPY --from=build  /app/web/public/noVNC/app /app/web/public/noVNC/app
COPY --from=build  /app/web/public/noVNC/core /app/web/public/noVNC/core
COPY --from=build  /app/web/public/noVNC/vendor /app/web/public/noVNC/vendor
COPY --from=build  /app/web/public/noVNC/*.html /app/web/public/noVNC/

EXPOSE 8080