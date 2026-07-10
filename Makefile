.PHONY: lint test build preflight

lint:
	golangci-lint run ./...

test:
	go test ./... -race -count=1

build:
	go build ./...

# CI gate (self-hosted runner): gofmt + vet + build + test. No golangci-lint here —
# lint is a pre-commit concern; preflight stays dependency-free so it never fails on a
# missing tool.
preflight:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }
	go vet ./...
	go build ./...
	go test ./... -race -count=1
