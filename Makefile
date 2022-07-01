LDFLAGS="-s -w"

build:
	mkdir -p ./bin
	CGO_ENABLED=0 go build -v -ldflags=${LDFLAGS} -o ./bin/dtapac
.PHONY: build

install:
	CGO_ENABLED=0 go install -v -ldflags=${LDFLAGS}
.PHONY: install

test:
	go test -v -cover ./...
.PHONY: test

lint:
	golangci-lint run
.PHONY: lint

clean:
	rm -rf ./bin
	go clean -testcache ./...
.PHONY: clean

docker:
	docker build -t nscuro/dtapac -f Dockerfile .
.PHONY: docker

generate-input-schemas:
	go run ./tools/schema-generator/main.go -output ./examples/schemas
.PHONY: generate-input-schemas

check-example-policies:
	opa check ./examples/policies --schema ./examples/schemas --strict --format pretty
.PHONY: check-example-policies

test-example-policies:
	opa test -v ./examples/policies
.PHONY: test-example-policies

build-example-bundle:
	opa build -o ./examples/bundles/dtapac.tar.gz -r $(shell date | sha256sum | cut -d ' ' -f 1) ./examples/policies
.PHONY: example-bundle

all: clean build test docker
.PHONY: all