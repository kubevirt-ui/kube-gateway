# build stage
FROM golang:1.15 AS build

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /app/ /app/cmd/... 

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