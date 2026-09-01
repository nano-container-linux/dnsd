FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/dnsd .

FROM alpine:3.24
RUN addgroup -S dnsd && adduser -S dnsd -G dnsd
WORKDIR /app

COPY --from=builder /out/dnsd /usr/local/bin/dnsd
COPY etc/dnsd /etc/dnsd

USER dnsd
EXPOSE 8053/udp 8053/tcp
ENTRYPOINT ["/usr/local/bin/dnsd", "run", "--config-dir", "/etc/dnsd"]
