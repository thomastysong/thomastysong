# hawkbell build entry points (GNU make). `make help` lists the targets.
#
# Every binary is static and reproducible: CGO off, -trimpath, no VCS stamp
# from the toolchain, an empty build id, and version/commit/date passed in.
# The release itself is built by goreleaser (.goreleaser.yaml); these
# targets are for development, CI and building packages without it.

GO        ?= go
DIST      ?= dist
# Package versions must be semantic versions (nfpm). The module lives in the
# hawkbell/ directory of its repository, so its version tags are
# hawkbell/vX.Y.Z (the go command's rule for a module in a subdirectory).
VERSION   ?= $(or $(shell git describe --tags --match 'hawkbell/v[0-9]*' --dirty 2>/dev/null | sed 's|^hawkbell/v||'),0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
DATE      ?= $(shell git log -1 --format=%cI 2>/dev/null)
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BUILD     := $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)'
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
PKG_ARCHS ?= amd64 arm64
NFPM      ?= nfpm
IMAGE     ?= hawkbell:$(VERSION)
GOOS_HOST := $(shell $(GO) env GOOS)

export CGO_ENABLED := 0

.PHONY: help build test vet fmt-check lint licenses-check rules bench e2e e2e-container cross package image image-binary release-snapshot clean

help: ## list the targets
	@awk -F':.*## ' '/^[a-z][a-z0-9-]*:.*## /{printf "  %-17s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## build dist/hawkbell for this machine
	$(BUILD) -o $(DIST)/hawkbell ./cmd/hawkbell

test: ## unit tests (no network, no docker)
	$(GO) test ./...

vet: ## go vet on every package
	$(GO) vet ./...

fmt-check: ## fail when a Go file is not gofmt-formatted
	@out=$$(find . -name '*.go' -not -path './vendor/*' -not -path './dist/*' -exec gofmt -l {} +); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet rules ## gofmt, go vet, staticcheck when installed, rule lint and tests
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipped"; fi

licenses-check: ## fail when THIRD_PARTY_LICENSES no longer matches the linked modules
	$(GO) run ./tools/licensegen -repo . -check

rules: build ## hawkbell rules lint (errors fail) and every rule's inline tests
	$(DIST)/hawkbell rules lint
	$(DIST)/hawkbell rules test

bench: ## scenario benchmark gate and report (bench/results is committed)
	$(GO) test ./internal/bench -run 'TestScenario' -count=1
	$(GO) run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out $(DIST)/bench

e2e: ## end-to-end tests that need only the local machine (CLI, extension)
	$(GO) test -tags e2e ./test/e2e -run 'CLI' -count=1 -v

e2e-container: ## container, package, Fluent Bit and Fleet-script tests (docker, local images, nfpm)
	HAWKBELL_E2E_CONTAINER=1 HAWKBELL_E2E_FLUENTBIT=1 HAWKBELL_E2E_FLEET=1 \
	  $(GO) test -tags e2e ./test/e2e -run 'Container|Package|FluentBit|FleetInstallScripts' -count=1 -v -timeout 30m

cross: ## build every release platform into dist/<os>_<arch>/
	@set -e; for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "$$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch $(BUILD) -o $(DIST)/$${os}_$${arch}/hawkbell$$ext ./cmd/hawkbell; \
	done

package: ## deb and rpm for PKG_ARCHS with nfpm (packaging/linux/nfpm.yaml stages dist/package/hawkbell)
	@command -v $(NFPM) >/dev/null 2>&1 || { echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.49.0 (the version the run records used; it needs Go 1.27.4 or later, which the go command downloads itself with GOTOOLCHAIN=auto, the default)"; exit 1; }
	@set -e; for arch in $(PKG_ARCHS); do \
	  GOOS=linux GOARCH=$$arch $(BUILD) -o $(DIST)/linux_$$arch/hawkbell ./cmd/hawkbell; \
	  mkdir -p dist/package; cp $(DIST)/linux_$$arch/hawkbell dist/package/hawkbell; \
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
