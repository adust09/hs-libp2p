# Multi-stage build for the go-libp2p responder used by the GET_VALUE
# round-trip interop check (docker-compose.kad-dht-go.yml).

FROM golang:1.26-bookworm@sha256:ea47ee45f1284d60f9cc09cb2c3bb4f508c256b640bd8bb30342ff13d1adcb52 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /out/kadserv-go .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /out/kadserv-go /kadserv-go
ENTRYPOINT ["/kadserv-go"]
