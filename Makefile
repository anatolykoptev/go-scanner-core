.PHONY: lint test build cover gostall preflight

GOSTALL_VERSION := v1.0.0
GOSTALL := $(shell command -v gostall 2>/dev/null || echo $$(go env GOPATH)/bin/gostall)

lint:
	golangci-lint run ./...

test:
	go test ./... -race -count=1

build:
	go build ./...

# Coverage report: prints the per-package + total percentage and writes
# coverage.out (gitignored) for `go tool cover -html` inspection.
cover:
	go test ./... -race -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

# CI gate (self-hosted runner): gofmt + vet + build + test. No golangci-lint here —
# lint is a pre-commit concern; preflight stays dependency-free so it never fails on a
# missing tool.
.PHONY: gostall

# Uses -lockorder -missingunlock -starvation only; -waitgroup -channel -livelock
# excluded (intra-procedural false positives on defer wg.Done() in goroutines,
# signal.Notify channels, and test spin loops).
gostall:
	@[ -x "$(GOSTALL)" ] || { echo "gostall not installed: go install github.com/erfanmomeniii/gostall/cmd/gostall@$(GOSTALL_VERSION)"; exit 1; }
	@echo "==> gostall"
	GOWORK=off "$(GOSTALL)" -lockorder -missingunlock -starvation ./...

preflight: gostall
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }
	go vet ./...
	go build ./...
	go test ./... -race -count=1
