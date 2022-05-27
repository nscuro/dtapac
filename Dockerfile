FROM golang:1.18.2-alpine3.16@sha256:4795c5d21f01e0777707ada02408debe77fe31848be97cf9fa8a1462da78d949 as build
RUN apk add --no-cache ca-certificates git make
WORKDIR /usr/src/app
COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN make install

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/dtapac /
ENTRYPOINT ["/dtapac"]