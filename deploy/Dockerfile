# build stage
FROM quay.io/fedora/fedora:34-x86_64 AS build
WORKDIR /app
RUN sudo dnf install -y git golang

RUN git clone https://github.com/yaacov/oc-gate.git /app \
  && git clone https://github.com/novnc/noVNC /app/web/public/noVNC \
  && go get github.com/yaacov/oc-gate/cmd/oc-gate \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/ /app/cmd/oc-gate/

# deploy stage

# quay does not have an alpine image,
# an option is to switch to using fedora-minimal
# another option is to use alpine (only from dockerhub)

# FROM quay.io/fedora/fedora-minimal:34-x86_64
FROM alpine

WORKDIR /app
RUN mkdir -p /app/wep/public/noVNC/

COPY --from=build /app/oc-gate /app/

COPY --from=build /app/web/public/default.css /app/web/public/
COPY --from=build /app/web/public/*.html /app/web/public/

COPY --from=build  /app/web/public/noVNC/app /app/web/public/noVNC/app
COPY --from=build  /app/web/public/noVNC/core /app/web/public/noVNC/core
COPY --from=build  /app/web/public/noVNC/vendor /app/web/public/noVNC/vendor
COPY --from=build  /app/web/public/noVNC/*.html /app/web/public/noVNC/

EXPOSE 8080