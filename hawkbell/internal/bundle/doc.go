// Package bundle moves detection content (rule packs, lists, suppressions and
// catalog overlays) to endpoints without shipping a new binary.
//
// A bundle is a gzip-compressed tar archive plus a detached signature. The
// archive holds manifest.json and nothing but these content files:
//
//	rules/<name>.yaml
//	catalog/<name>.yaml
//	lists.yaml
//	suppressions.yaml
//
// The signature is Ed25519 over the SHA-256 digest of the archive bytes (64
// raw bytes, published next to the archive as <name>.sig). It can be checked
// without hawkbell:
//
//	openssl dgst -sha256 -binary bundle.tgz > digest
//	openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in digest -sigfile bundle.tgz.sig
//
// # Trust model
//
// The transport and the host that serves the bundle are not trusted. Only a
// signature made with one of the configured public keys makes content
// acceptable, and nothing is decompressed or parsed before the signature has
// been checked over the raw bytes.
//
// A valid signature does not make the archive safe to unpack. A stolen
// signing key must cost the fleet its detection content, not a root file
// write, so the archive is read with a parser that refuses everything the
// format does not need: entries that are not regular files, extended (PAX)
// headers, duplicate names, names that collide on a case-insensitive
// filesystem, Windows device names, path traversal, names outside the
// allow-list, more than MaxFiles entries, more than MaxBytes of content,
// concatenated gzip members and bytes after the end-of-archive marker.
// Extraction goes through os.Root, so even a name that slipped through the
// checks could not leave the staging directory.
//
// A host only moves forward: Install refuses a version that is not higher
// than the installed one, so a replayed old bundle (which still carries a
// valid signature) cannot roll detection content back.
//
// Install accepts only a Manifest that Verify returned for the same bytes.
// There is no way to install a tarball whose signature was not checked.
//
// The installed copy is protected by filesystem permissions, not by the
// signature: whoever can write the destination directory can change what the
// sensor loads. On Unix, Installed, Current and Install therefore refuse a
// destination, version directory, pointer or manifest that is writable by
// group or others, or owned by anyone but root or the calling user.
//
// # On-disk layout
//
//	<destDir>/current      one line of JSON naming the active version
//	<destDir>/v<N>/        the content of version N, exactly as signed
//	<destDir>/v<N>.tmp/    staging directory of an install in progress
//	<destDir>/pull.json    ETag of the last successful Pull (mode 0600)
//	<destDir>/.lock        serialises installers across processes
//
// A version directory is created by renaming a fully written and synced
// staging directory, and the pointer is replaced by rename, so a reader sees
// the old bundle or the new one and never a mixture. The previous version
// directory is kept until the install after next, so a process that resolved
// Current just before a switch can finish reading. Directories are 0755 and
// files 0644 whatever the umask, because unprivileged hook processes read
// them.
//
// # Loading installed content
//
// Readers should take the file list from Manifest.Paths and read through
// ReadFile, which checks every file against the manifest. Globbing the
// version directory would also load a file that was planted there later.
//
// # Not supported
//
//   - Expiry. A server (or an attacker in its place) that keeps answering
//     with the installed version, or with 304, freezes a host on old content.
//     Manifest.Created is exposed so the caller can report bundle age.
//   - Key revocation lists. Removing a public key from the configuration
//     stops future installs signed with it; content already installed stays
//     until a newer bundle replaces it.
//   - Permission checks on Windows. ACLs on the destination directory are
//     the installer's responsibility there; this package checks nothing.
//   - YAML validation. The package depends only on the standard library and
//     treats content as opaque bytes. A caller that can parse the content
//     passes a Validate callback, which runs on the staged files before they
//     become current.
//   - Cross-process locking on platforms other than Linux, macOS, the BSDs
//     and Windows: installers are serialised within one process only.
//   - Byte-for-byte reproducible archives across Go releases. Create is
//     deterministic for a given toolchain, input and CreateOptions.Created,
//     but compress/flate output may change between Go versions.
package bundle
