// Package sink writes events to their destinations.
//
// The design has one durable queue and nothing else: the Files sink appends
// every event to NDJSON segment files, and that directory is both the local
// forensic log and the contract with Fluent Bit's tail input. Network
// delivery never buffers in memory behind the caller's back. Either Fluent
// Bit tails the segments, or a Shipper tails them itself and feeds a network
// Sink (Forward or OTLP) with at-least-once delivery, checkpointing only
// what the destination acknowledged.
//
// Sinks:
//   - NewFiles: append-only NDJSON segments with size roll and pruning.
//   - NewStdout: one line per event to a writer (containers, debugging).
//   - NewForward: Fluent Forward protocol v1 client, PackedForward with ack.
//   - NewOTLP: OTLP/HTTP JSON logs exporter.
//   - NewShipper: segment tailer that drives a network Sink.
//
// Threat model. The attacker controls agent output and therefore event
// content, and in daemonless mode may be able to write to the segment
// directory. Event content cannot break framing (one event is one JSON line;
// oversize events are shrunk, never split), segment files are opened without
// following symlinks and must be regular single-link files, and only files
// whose names parse as segments are ever read or deleted. Network replies
// (acks, handshake, HTTP bodies) are size and depth bounded.
//
// Not supported: Forward "empty_shared_key" servers (set a key), zstd
// compression on Forward (gzip only), OTLP over gRPC or protobuf, and atomic
// appends on network filesystems (NFS does not guarantee O_APPEND atomicity,
// so keep the segment directory on local disk).
package sink

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/format"
)

// Sink is a destination for events. Write returns nil only when the whole
// batch was accepted by the destination (for network sinks: acknowledged).
// Implementations are safe for concurrent use.
type Sink interface {
	Name() string
	Write(batch []*event.Event) error
	Flush() error
	Close() error
}

// Line formats accepted by the Files and Stdout sinks.
const (
	FormatNative = "native"
	FormatOCSF   = "ocsf"
)

// ErrClosed is returned by a sink used after Close.
var ErrClosed = errors.New("sink: closed")

// Pruner is implemented by sinks that keep local data and can enforce their
// retention limits on demand. The Files sink prunes whenever it creates a
// segment; a long-running daemon may also call Prune on a timer.
type Pruner interface {
	Prune() error
}

// IsPermanent reports whether err says that resending the same data cannot
// succeed (for example an HTTP 400 from an OTLP receiver). The Shipper uses
// it to isolate and drop a poisoned record instead of stalling forever.
func IsPermanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

func checkFormat(f string) (string, error) {
	switch f {
	case "", FormatNative:
		return FormatNative, nil
	case FormatOCSF:
		return FormatOCSF, nil
	}
	return "", fmt.Errorf("sink: unknown format %q (want %s or %s)", f, FormatNative, FormatOCSF)
}

// encodeLine returns the event as exactly one line, newline included.
// encoding/json escapes every control character inside strings, so the only
// raw newline is the terminator.
func encodeLine(e *event.Event, f string) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	if f == FormatOCSF {
		b, err = json.Marshal(format.OCSF(e))
	} else {
		b, err = format.NativeJSON(e)
	}
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
