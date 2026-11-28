# Multi-stage build for the go-libp2p responder used by the GET_VALUE
# round-trip interop check (docker-compose.kad-dht-go.yml).

FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /out/kadserv-go .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/kadserv-go /kadserv-go
ENTRYPOINT ["/kadserv-go"]
