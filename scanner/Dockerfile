FROM golang:1.27 AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o scanner .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY --from=builder /app/scanner .

EXPOSE 8081

CMD ["./scanner"]
