FROM golang:1.21.5-alpine3.18@sha256:5c1cabd9a3c6851a3e18735a2c133fbd8f67fe37eb3203318b7af2ffd2547095 as build
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