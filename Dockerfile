FROM golang:alpine AS builder

WORKDIR /app

COPY . /app

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o velka .

FROM alpine:latest

COPY --from=builder /app/velka /usr/local/bin