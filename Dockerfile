# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o atop-exporter .

# Stage 2: Runtime
FROM scratch

COPY --from=builder /app/atop-exporter /atop-exporter

# Expose metric port
EXPOSE 9105

# Run
ENTRYPOINT ["/atop-exporter"]
