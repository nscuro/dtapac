FROM golang:1.21.4-alpine3.18@sha256:a2043ef0528eeb3cb9884b703794ad472930e4dcd109490cddf8b5cf519efa17 as build
RUN apk add --no-cache ca-certificates git make
WORKDIR /usr/src/app
COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN make install

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/dtapac /
USER 1000
ENTRYPOINT ["/dtapac"]