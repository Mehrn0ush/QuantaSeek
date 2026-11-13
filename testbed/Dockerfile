# QuantaSeek testbed servers: OpenSSL 3.5 s_server and a Go crypto/tls server.
# Base images are pinned by multi-arch index digest (linux/amd64 and linux/arm64).

FROM golang:1.27-alpine3.23@sha256:7a93747afee80359e81dbe39c8a65037b147cada0262bf86f5b96dd06842b368 AS gobuild
WORKDIR /src
COPY go/go.mod go/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /goserver .

FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2
# Exact package version: the expected values in tests/testbed.rs were
# confirmed against this build (see testbed/README.md).
RUN apk add --no-cache openssl=3.5.9-r0
COPY --from=gobuild /goserver /usr/local/bin/goserver
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
