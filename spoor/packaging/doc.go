// Package packaging holds spoor's service definitions and package build
// inputs (no Go code is shipped from here):
//
//   - systemd/spoor.service, launchd/com.github.thomastysong.spoor.plist,
//     windows/install-service.ps1: the service definitions;
//     deploy/fleet/scripts/install-spoor.sh embeds the first two and a test
//     in internal/fleetgen keeps them identical;
//   - linux/: nfpm configuration and the deb/rpm maintainer scripts;
//   - macos/: the installer package's post-install script and a pkgbuild
//     wrapper (untested: no macOS host);
//   - windows/spoor.wxs: a WiX installer sketch (untested);
//   - container/filecap: the tool the Dockerfile's build stage uses to put
//     file capabilities on the node sensor binary.
//
// The tests in this directory check that these files agree with each other,
// with .goreleaser.yaml, with the Dockerfile and with deploy/kubernetes.
// README.md says what was built and installed for real.
package packaging
