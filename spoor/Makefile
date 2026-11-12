# spoor build entry points (GNU make). `make help` lists the targets.
#
# Every binary is static and reproducible: CGO off, -trimpath, no VCS stamp
# from the toolchain, an empty build id, and version/commit/date passed in.
# The release itself is built by goreleaser (.goreleaser.yaml); these
# targets are for development, CI and building packages without it.

GO        ?= go
DIST      ?= dist
# Package versions must be semantic versions (nfpm): v-prefixed tags only.
VERSION   ?= $(or $(shell git describe --tags --match 'v[0-9]*' --dirty 2>/dev/null | sed 's/^v//'),0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
DATE      ?= $(shell git log -1 --format=%cI 2>/dev/null)
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BUILD     := $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)'
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
PKG_ARCHS ?= amd64 arm64
NFPM      ?= nfpm
IMAGE     ?= spoor:$(VERSION)
GOOS_HOST := $(shell $(GO) env GOOS)

export CGO_ENABLED := 0

.PHONY: help build test vet fmt-check lint rules bench e2e e2e-container cross package image image-binary release-snapshot clean

help: ## list the targets
	@awk -F':.*## ' '/^[a-z][a-z-]*:.*## /{printf "  %-17s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## build dist/spoor for this machine
	$(BUILD) -o $(DIST)/spoor ./cmd/spoor

test: ## unit tests (no network, no docker)
	$(GO) test ./...

vet: ## go vet on every package
	$(GO) vet ./...

fmt-check: ## fail when a Go file is not gofmt-formatted
	@out=$$(gofmt -l $$(git ls-files '*.go' 2>/dev/null || find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet rules ## gofmt, go vet, staticcheck when installed, rule lint and tests
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipped"; fi

rules: build ## spoor rules lint (errors fail) and every rule's inline tests
	$(DIST)/spoor rules lint
	$(DIST)/spoor rules test

bench: ## scenario benchmark gate and report (bench/results is committed)
	$(GO) test ./internal/bench -run 'TestScenario' -count=1
	$(GO) run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out $(DIST)/bench

e2e: ## end-to-end tests that need only the local machine (CLI, extension)
	$(GO) test -tags e2e ./test/e2e -run 'CLI' -count=1 -v

e2e-container: ## container, package, Fluent Bit and Fleet-script tests (docker, local images, nfpm)
	SPOOR_E2E_CONTAINER=1 SPOOR_E2E_FLUENTBIT=1 SPOOR_E2E_FLEET=1 \
	  $(GO) test -tags e2e ./test/e2e -run 'Container|Package|FluentBit|FleetInstallScripts' -count=1 -v -timeout 30m

cross: ## build every release platform into dist/<os>_<arch>/
	@set -e; for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "$$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch $(BUILD) -o $(DIST)/$${os}_$${arch}/spoor$$ext ./cmd/spoor; \
	done

package: ## deb and rpm for PKG_ARCHS with nfpm (packaging/linux/nfpm.yaml stages dist/package/spoor)
	@command -v $(NFPM) >/dev/null 2>&1 || { echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@set -e; for arch in $(PKG_ARCHS); do \
	  GOOS=linux GOARCH=$$arch $(BUILD) -o $(DIST)/linux_$$arch/spoor ./cmd/spoor; \
	  mkdir -p dist/package; cp $(DIST)/linux_$$arch/spoor dist/package/spoor; \
	  for fmt in deb rpm; do VERSION=$(VERSION) ARCH=$$arch $(NFPM) package -f packaging/linux/nfpm.yaml -p $$fmt -t $(DIST)/; done; \
	done; rm -rf dist/package

image: ## node sensor image from the Dockerfile (file capabilities applied in the build stage)
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE) .

image-binary: ## the bare binary through the Dockerfile's `binary` target, into dist/image/
	docker build --target binary --build-arg VERSION=$(VERSION) --output type=local,dest=$(DIST)/image .

release-snapshot: ## goreleaser dry run: archives, packages, checksums (no signing, no publishing)
	goreleaser release --snapshot --clean --skip=sign,sbom,publish

clean: ## remove dist/
	rm -rf $(DIST)
