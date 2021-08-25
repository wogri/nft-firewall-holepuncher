FROM golang:alpine AS builder
COPY . /build/
WORKDIR /build/
RUN apk update && apk upgrade && apk add --no-cache ca-certificates make
RUN update-ca-certificates

WORKDIR /build/server
RUN make static
WORKDIR /build/client
RUN make static

FROM scratch
COPY --from=builder /build/server/static /server
COPY --from=builder /build/client/static /client
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY passwd /etc/passwd
COPY group /etc/group
USER daemon:daemon
ENTRYPOINT ["/server"]
