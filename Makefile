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
# works — main.go falls back to the module's build info. DATE is the commit's time,
# not the build's, so every input is fixed by the commit and two builds of it hash
# the same.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell TZ=UTC0 git show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# A release-signing key to trust besides the built-in ones, for trying the
# self-update against a local release: `make build VERSION=v0.0.1
# RELEASE_TEST_KEY=$(go run ./tools/releasesign pubkey -key k.pem)`. Such a build
# says so in `clair version`, and `make dist` refuses it (ADR 2026-09.qk6v).
RELEASE_TEST_KEY ?=
ifneq ($(RELEASE_TEST_KEY),)
LDFLAGS += -X main.releaseTestKey=$(RELEASE_TEST_KEY)
endif

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

# Nobody runs the darwin builds on a Mac before a release, and Apple silicon kills
# an arm64 binary whose code signature is missing or stale at exec. Go's linker
# signs it ad hoc; tools/machocheck verifies every page hash the way the kernel will.
DARWIN_BUILDS := $(patsubst darwin/%,dist/clair-darwin-%,$(filter darwin/%,$(PLATFORMS)))

.PHONY: build-all
build-all: ## Cross-compile every supported platform into ./dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		echo "  $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_BUILD) -o dist/clair-$$os-$$arch$$ext ./cmd/clair || exit 1; \
	done
	go run ./tools/machocheck $(DARWIN_BUILDS)

# What the tag pipeline uploads (ADR 2026-09.zvs8): every platform, stamped with a
# release version, and the checksums the installers verify. `make dist VERSION=v0.1.0`
# reproduces it; it refuses a version that is not a release tag.
.PHONY: dist
dist: build-all ## build-all for a release: check the stamped version, write dist/SHA256SUMS.txt
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || \
		{ echo "dist: VERSION=$(VERSION) is not a vX.Y.Z release tag" >&2; exit 1; }
	@[ -z "$(RELEASE_TEST_KEY)" ] || \
		{ echo "dist: RELEASE_TEST_KEY is set; a release trusts only the built-in keys" >&2; exit 1; }
	@go run ./tools/releasesign builtin > /dev/null || \
		{ echo "dist: a release needs the primary and backup release keys built in" >&2; exit 1; }
	@host=dist/clair-$$(go env GOOS)-$$(go env GOARCH)$$( [ "$$(go env GOOS)" = windows ] && echo .exe); \
		$$host version | grep -q "^clair $(VERSION) " || \
		{ echo "dist: $$host reports '$$($$host version)', not $(VERSION)" >&2; exit 1; }; \
		! $$host version | grep -q "release test key" || \
		{ echo "dist: $$host was built with a release test key" >&2; exit 1; }; \
		! go version -m $$host | grep -q 'vcs.modified=true' || \
		{ echo "dist: $$host was built from a modified checkout; git status must be clean" >&2; exit 1; }
	cd dist && rm -f SHA256SUMS.txt && sha256sum clair-* > SHA256SUMS.txt
	@cat dist/SHA256SUMS.txt

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

# Once per OS the agent ships for, whatever the host: a _darwin.go or _windows.go
# file, and its tests, is otherwise never type-checked or linted before a user on
# that OS runs it.
LINT_OSES := linux darwin windows

.PHONY: lint
lint: $(BIN)/golangci-lint ## Static analysis (.golangci.yml: vet, staticcheck, gosec, revive, …) for every OS
	@for os in $(LINT_OSES); do \
		echo "  GOOS=$$os"; \
		GOOS=$$os $(BIN)/golangci-lint run || exit 1; \
	done

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
