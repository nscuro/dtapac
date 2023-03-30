FROM golang:1.20.2-alpine3.16@sha256:1d7fec2b8f451917a45b3e41249d1b5474c5269cf03f5cbdbd788347a1f1237c as build
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