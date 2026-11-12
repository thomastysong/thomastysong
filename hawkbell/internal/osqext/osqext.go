package osqext

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	osquery "github.com/osquery/osquery-go"
)

// Name is the name the extension registers under; it is what
// "SELECT name FROM osquery_extensions" shows.
const Name = "hawkbell"

// Version is reported to osquery as the extension version. The command that
// embeds this package sets it before calling Run.
var Version = "dev"

// Logf receives the few diagnostics the extension produces (host id
// problems). osquery captures an extension's standard error, which is where
// the default writes.
var Logf = log.New(log.Writer(), "hawkbell extension: ", log.LstdFlags).Printf

// ErrOsqueryGone is returned by Run when osquery stopped answering pings:
// the ordinary way an extension's life ends when osquery exits or restarts
// its worker. Callers normally treat it as a clean exit.
var ErrOsqueryGone = errors.New("osquery is no longer reachable")

const (
	defaultTimeout  = 3 * time.Second // osquery's own --extensions_timeout default
	defaultInterval = 3 * time.Second // and --extensions_interval
	// writeBuffer batches the Thrift response. Unbuffered, the binary
	// protocol issues one write per field: several hundred thousand system
	// calls for a full 10,000-row table.
	writeBuffer = 64 << 10
)

// Run registers one osquery table per state.Tables entry (typed columns,
// equality and time-range constraints pushed down to SQLite) and serves them
// from the state database at dbPath until osquery shuts the extension down
// or goes away. socket is osquery's extension manager socket (a named pipe
// on Windows); timeout bounds connecting to it and interval is how often
// osquery is pinged. Non-positive values mean osquery's defaults (3 s).
//
// When hostIDFile is not empty, Run also asks osquery once for
// "SELECT uuid FROM system_info" and writes the answer there with mode 0644,
// so the daemon and the hooks use the host id Fleet knows. That happens in
// the background, with a few retries, and never delays or fails the tables.
//
// The database need not exist: until it does, every table is empty.
func Run(socket string, timeout, interval time.Duration, dbPath, hostIDFile string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("osqext: internal error: %v", r)
		}
	}()
	if strings.TrimSpace(socket) == "" {
		return errors.New("osqext: no extension socket given")
	}
	if strings.TrimSpace(dbPath) == "" {
		return errors.New("osqext: no state database path given")
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if interval <= 0 {
		interval = defaultInterval
	}

	srv, err := osquery.NewExtensionManagerServer(Name, socket,
		osquery.ServerTimeout(timeout),
		osquery.ServerPingInterval(interval),
		osquery.ExtensionVersion(Version),
		osquery.WithTransportFactory(thrift.NewTBufferedTransportFactory(writeBuffer)),
	)
	if err != nil {
		return fmt.Errorf("osqext: connect to osquery at %s: %w", socket, err)
	}
	src := newSource(dbPath)
	defer src.close()
	srv.RegisterPlugin(plugins(src)...)

	stop := make(chan struct{})
	defer close(stop)
	if hostIDFile != "" {
		go syncHostID(stop, func() (rowQuerier, func(), error) {
			// A connection of its own: the server's client is busy with
			// registration and pings, and is not exposed anyway.
			c, err := osquery.NewClient(socket, timeout)
			if err != nil {
				return nil, nil, err
			}
			return c, c.Close, nil
		}, hostIDFile)
	}

	err = srv.Run()
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "ping failed"), strings.Contains(err.Error(), "ping returned status"):
		return fmt.Errorf("%w: %v", ErrOsqueryGone, err)
	default:
		return fmt.Errorf("osqext: %w", err)
	}
}
