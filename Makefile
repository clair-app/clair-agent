# Clair agent — build, check and release-shape targets.
#
# `make check` is the finishing gate: everything CI runs, in the order it fails
# fastest. Tools are pinned here and installed into ./bin (gitignored) so a clone,
# a worktree and the CI image all lint with the same version; nothing is taken
# from $GOPATH/bin. Bump a version here and the stamp file forces a reinstall.

MODULE := claircode.app/clair-agent
BIN    := $(CURDIR)/bin

GOLANGCI_LINT_VERSION := v2.13.2
GOVULNCHECK_VERSION   := v1.8.0

# Injected into cmd/clair; `clair version` reports them. A plain `go build` still
# works — main.go falls back to the module's build info.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# The agent is a static binary for a `curl | sh` install (RELAY.md §15): no cgo,
# no build path in the panics, reproducible for a given commit. CGO_ENABLED=0 is
# scoped to the build targets — the race detector in `make test` needs cgo.
GOFLAGS_BUILD := -trimpath -ldflags '$(LDFLAGS)'

.DEFAULT_GOAL := check

.PHONY: help
help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------- build

.PHONY: build
build: ## Build ./bin/clair for this host
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o $(BIN)/clair ./cmd/clair

# The three install targets RELAY.md names (Windows last). Cross-compiling here
# catches an OS-specific import before a user on that OS does.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build-all
build-all: ## Cross-compile every supported platform into ./dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		echo "  $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_BUILD) -o dist/clair-$$os-$$arch$$ext ./cmd/clair || exit 1; \
	done

.PHONY: run
run: ## Run the agent from source: make run ARGS="version"
	go run ./cmd/clair $(ARGS)

# ----------------------------------------------------------------------- checks

.PHONY: check
check: tidy-check fmt-check lint test vuln adr-check ## Everything CI runs (the finishing gate)

.PHONY: test
test: ## Unit tests with the race detector, shuffled, coverage to coverage.out
	go test -race -shuffle=on -count=1 -coverprofile=coverage.out ./...

.PHONY: cover
cover: test ## Open the coverage report
	go tool cover -html=coverage.out

.PHONY: lint
lint: $(BIN)/golangci-lint ## Static analysis (.golangci.yml: vet, staticcheck, gosec, revive, …)
	$(BIN)/golangci-lint run

.PHONY: fmt
fmt: $(BIN)/golangci-lint ## Rewrite files with gofumpt + goimports
	$(BIN)/golangci-lint fmt

.PHONY: fmt-check
fmt-check: $(BIN)/golangci-lint ## Fail if fmt would change anything
	$(BIN)/golangci-lint fmt --diff

.PHONY: vuln
vuln: $(BIN)/govulncheck ## Known vulnerabilities reachable from this module
	$(BIN)/govulncheck ./...

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod / go.sum are not tidy
	go mod tidy -diff

# ------------------------------------------------------------------------- ADRs

.PHONY: adr-new
adr-new: ## Scaffold a decision: make adr-new TITLE="…" TOPICS=a,b
	@test -n "$(TITLE)" || { echo 'usage: make adr-new TITLE="<title>" [TOPICS=a,b]' >&2; exit 2; }
	go run ./tools/adr new "$(TITLE)" -topics "$(TOPICS)"

.PHONY: adr-index
adr-index: ## Regenerate .agents/memory/decisions.md
	go run ./tools/adr index

.PHONY: adr-check
adr-check: ## Fail if the ADR router is stale
	go run ./tools/adr index -check

# ------------------------------------------------------------------------ tools

.PHONY: tools
tools: $(BIN)/golangci-lint $(BIN)/govulncheck ## Install the pinned tools into ./bin

# A stamp per (tool, version): bumping the pin above invalidates it, and the
# binary is rebuilt from the module proxy with its checksum verified.
$(BIN)/golangci-lint: $(BIN)/.golangci-lint@$(GOLANGCI_LINT_VERSION)
$(BIN)/.golangci-lint@%:
	GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$*
	@rm -f $(BIN)/.golangci-lint@* && touch $@

$(BIN)/govulncheck: $(BIN)/.govulncheck@$(GOVULNCHECK_VERSION)
$(BIN)/.govulncheck@%:
	GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$*
	@rm -f $(BIN)/.govulncheck@* && touch $@

.PHONY: hooks
hooks: ## Opt this clone into .githooks (pre-commit ADR router check)
	git config core.hooksPath .githooks

.PHONY: clean
clean: ## Remove build outputs (keeps ./bin tools)
	rm -rf dist coverage.out $(BIN)/clair
