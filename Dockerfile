# build stage
FROM registry.access.redhat.com/ubi8/go-toolset:latest AS build

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/ /app/...

# deploy stage
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

WORKDIR /app
RUN mkdir -p /app/web/

# copy proxy server
COPY --from=build /app/kube-gateway /app/

# copy static web app
COPY ./web/public /app/web/