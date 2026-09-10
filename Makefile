GO ?= go
BIN := bin/abnormal-mcp

.PHONY: all build test test-access test-phase34 vet fmt vuln check

all: check build

build:
	@mkdir -p bin
	$(GO) build -o $(BIN) ./cmd/abnormal-mcp

test:
	$(GO) test ./...

test-access:
	@bash scripts/test-access.sh

test-phase34:
	@bash scripts/test-phase34.sh

vet:
	$(GO) vet ./...

fmt:
	@test -z "$$($(GO)fmt -l .)" || ($(GO)fmt -l . && exit 1)

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: fmt vet test
