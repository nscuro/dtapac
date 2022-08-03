FROM golang:1.19.0-alpine3.16@sha256:f734a85923ff49da7caf82940b422bf679ca9bdec38cc56f501a4745b557d150 as build
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