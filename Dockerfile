# build stage
FROM golang:1.15 AS build

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /app/ /app/cmd/... 

# deploy stage
FROM alpine

WORKDIR /app
RUN mkdir -p /app/web/public/

COPY --from=build /app/oc-gate /app/

COPY --from=build /app/web/public/default.css /app/web/public/
COPY --from=build /app/web/public/login.html /app/web/public/index.html
