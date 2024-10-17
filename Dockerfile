FROM golang:1.22 AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o main .

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y traceroute

WORKDIR /app

COPY --from=builder /app/main .

VOLUME /app/logs

CMD ["./main"]