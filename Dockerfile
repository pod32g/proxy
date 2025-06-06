# Build stage
FROM golang:1.23-bullseye AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o proxy ./

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/proxy /usr/local/bin/proxy
EXPOSE 8080 8443
ENTRYPOINT ["proxy"]
CMD ["-http", ":8080"]

