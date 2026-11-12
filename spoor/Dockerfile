# spoor container image: the Kubernetes node sensor (deploy/kubernetes).
#
#   docker build -t spoor:dev .
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=1.2.3 --build-arg COMMIT=$(git rev-parse --short=12 HEAD) \
#     --build-arg DATE=$(git log -1 --format=%cI) -t REGISTRY/spoor:1.2.3 --push .
#   docker build --target binary --output type=local,dest=dist/ .   # the bare binary
#
# What the image is (deploy/kubernetes/README.md has the reasons):
#   - a static, CGO-free binary at /usr/bin/spoor on distroless/static,
#     running as uid/gid 65532 (nonroot), entrypoint `spoor run`;
#   - the binary carries two FILE capabilities, cap_dac_read_search and
#     cap_sys_ptrace, with the effective bit (setcap ...=ep). A non-root
#     process gets capabilities only from file capabilities: capabilities a
#     pod adds to a non-root container land in its bounding set but are not
#     effective (red team E1, variant I: CapEff=0). With the file
#     capabilities, a uid-65532 sensor reads other users' /proc/<pid>/environ
#     and 0700 homes (and any file and process memory on the node: that is
#     what the two capabilities grant). File permissions still stop it from
#     writing root-owned files in other containers, which a uid-0 sensor with
#     the same two capabilities can (red team E2, W3): CAP_DAC_READ_SEARCH
#     bypasses read and search checks only. CAP_SYS_PTRACE with the host pid
#     namespace would still let it attach to any root process and rewrite it
#     (ptrace, process_vm_writev, pidfd_getfd), which the runtime's default
#     seccomp profile allows to a holder of the capability: run it with
#     deploy/kubernetes/seccomp/node-sensor.json, the default profile without
#     those calls (the DaemonSet does; `docker run --security-opt
#     seccomp=...` elsewhere). Without it a compromised sensor is equivalent
#     to root on the node;
#   - because the effective bit is set, the kernel refuses to execute the
#     binary (EPERM) unless both capabilities are in the container's bounding
#     set: the image starts only with `--cap-add SYS_PTRACE --cap-add
#     DAC_READ_SEARCH` (securityContext.capabilities.add in Kubernetes) and
#     allowPrivilegeEscalation left true (no_new_privs disables file
#     capabilities). A misconfigured sensor fails to start instead of running
#     blind. For anything else (in-image hook mode, CI, `spoor detect`) use
#     the release binary or the `binary` target, which has no capabilities.
#
# Base images come from mirror.gcr.io and gcr.io (Docker Hub rate-limits
# anonymous pulls) and are pinned by digest so a rebuild of the same commit
# uses the same toolchain and base. The Dockerfile has no `# syntax=` line on
# purpose: that would pull the Dockerfile frontend from Docker Hub; the
# features used here (RUN --mount, COPY --chown, dynamic platform args) are
# in the frontend built into BuildKit.
#
# Reproducibility: -trimpath, -buildvcs=false with version, commit and date
# passed as build arguments, an empty build id, CGO off. A `vendor/`
# directory in the build context is used when present (offline builds).

ARG GO_IMAGE=mirror.gcr.io/library/golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG DATE=
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/binary/spoor ./cmd/spoor
# File capabilities go on a copy that only the sensor image gets. filecap
# runs on the build platform (no GOOS/GOARCH here) and writes exactly what
# setcap(8) writes; `verify` fails the build when the attribute did not stick
# (a build filesystem without xattr support).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    install -d -m 0755 /out/sensor/usr/bin \
 && install -d -m 0700 /out/sensor/var/lib/spoor \
 && install -m 0755 /out/binary/spoor /out/sensor/usr/bin/spoor \
 && go run ./packaging/container/filecap set cap_dac_read_search,cap_sys_ptrace=ep /out/sensor/usr/bin/spoor \
 && go run ./packaging/container/filecap verify cap_dac_read_search,cap_sys_ptrace=ep /out/sensor/usr/bin/spoor

# The bare binary, without file capabilities.
FROM scratch AS binary
COPY --from=build /out/binary/spoor /spoor
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/spoor/

# The node sensor (default target).
FROM ${BASE_IMAGE} AS sensor
ARG VERSION=dev
LABEL org.opencontainers.image.title="spoor" \
      org.opencontainers.image.description="AI agent detection sensor: Kubernetes node sensor" \
      org.opencontainers.image.source="https://github.com/thomastysong/thomastysong/tree/main/spoor" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
# BuildKit's COPY keeps the security.capability attribute (verified by
# test/e2e/container_test.go on the built image; see deploy/kubernetes/VERIFIED.md).
COPY --from=build /out/sensor/usr/bin/spoor /usr/bin/spoor
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/spoor/
# Default data directory for `docker run`; Kubernetes mounts an emptyDir here
# (the root filesystem is read-only there).
COPY --from=build --chown=65532:65532 /out/sensor/var/lib/spoor /var/lib/spoor
USER 65532:65532
ENTRYPOINT ["/usr/bin/spoor"]
CMD ["run", "--config", "/etc/spoor/spoor.yaml"]
