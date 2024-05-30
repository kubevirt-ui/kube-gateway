# build stage
FROM registry.access.redhat.com/ubi8/go-toolset:latest AS build

WORKDIR /app
COPY . .

USER 0
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -o /app/ /app/...

# deploy stage
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

WORKDIR /app
RUN mkdir -p /app/web/public

# copy proxy server
COPY --from=build /app/kube-gateway /app/

# copy static web app
COPY ./web/public /app/web/public/