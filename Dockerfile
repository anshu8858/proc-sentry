# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o proc-sentry .

# Stage 2: Runtime
FROM scratch

COPY --from=builder /app/proc-sentry /proc-sentry

# Expose metric port
EXPOSE 9105

# Run
ENTRYPOINT ["/proc-sentry"]
