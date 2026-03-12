# Stage 1: Build
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o /bin/chaos-sec ./cmd/chaos-sec/

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bin/chaos-sec /chaos-sec
ENTRYPOINT ["/chaos-sec"]
