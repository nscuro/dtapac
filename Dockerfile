FROM golang:1.19.0-alpine3.16@sha256:0e78fc17d9b4428bc6b9c07aa49c819541a99cd0c0121c4de9c68feecfea825b as build
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