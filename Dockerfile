FROM golang:1.23.1-alpine3.20@sha256:fbc3a217775ee3ec2328077ad4f3681bbc2c4a812d63cc8c857c827f1e8e971f AS build
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