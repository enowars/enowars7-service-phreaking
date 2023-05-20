FROM golang:1.20-bullseye AS builder

COPY src/ /checker/
WORKDIR /checker

RUN go mod download

RUN CGO_ENABLED=0 go build -ldflags="-extldflags '-static' -s -w" ./cmd/checker

FROM scratch
WORKDIR /app
COPY --from=builder /checker .
EXPOSE 3303
CMD ["./checker"]