package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/osqext"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// extArgs are the flags osquery passes to an extension. osquery may add
// flags in future releases; unknown ones are ignored rather than refused,
// because a refusal would make the extension crash-loop under osquery.
type extArgs struct {
	socket   string
	timeout  time.Duration
	interval time.Duration
	config   string
}

func parseExtArgs(args []string) extArgs {
	var e extArgs
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		next := func() string {
			if hasVal {
				return val
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				return args[i]
			}
			return ""
		}
		switch name {
		case "socket":
			e.socket = next()
		case "timeout":
			e.timeout = seconds(next())
		case "interval":
			e.interval = seconds(next())
		case "config":
			e.config = next()
		}
	}
	return e
}

// seconds reads osquery's whole-second flag values; anything else means
// "osquery's default".
func seconds(s string) time.Duration {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 3600 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// runExtension serves the state database as osquery tables. osquery starts
// the binary from its autoload file (/usr/lib/hawkbell/hawkbell.ext,
// /usr/local/lib/hawkbell/hawkbell.ext, Program Files\hawkbell\hawkbell.ext.exe) with
// no hawkbell arguments, so the database is found the way the daemon finds it:
// the default configuration file, or --config when given.
func runExtension(args []string, stderr io.Writer) int {
	e := parseExtArgs(args)
	osqext.Version = versionString()
	if e.socket == "" {
		fmt.Fprintln(stderr, "hawkbell extension: no --socket given (osquery passes it when it starts an extension)")
		return exitUsage
	}
	path := e.config
	if path == "" {
		path = defaultConfigPath()
	}
	cfg, err := config.Load(path, platform.DefaultDirs().Data)
	if err != nil {
		// A config that fails validation still names the data directory,
		// and the tables only need that. A file that cannot be read at all
		// leaves the default location; a wrong database then reads as zero
		// rows, which the fail-closed policies treat as unhealthy.
		fmt.Fprintf(stderr, "hawkbell extension: config %s: %v\n", path, err)
		if cfg == nil {
			cfg = config.Default(platform.DefaultDirs().Data)
		}
	}
	err = osqext.Run(e.socket, e.timeout, e.interval, cfg.StateDB(), extHostIDFile())
	if err != nil && !errors.Is(err, osqext.ErrOsqueryGone) {
		fmt.Fprintf(stderr, "hawkbell extension: %v\n", err)
		return exitError
	}
	return exitOK
}

// extHostIDFile is where the extension records osquery's host uuid: the
// system config directory, which every hawkbell process reads first. An
// unprivileged extension (a developer's own osqueryi) writes nothing.
func extHostIDFile() string {
	if !platform.IsPrivileged() {
		return ""
	}
	return filepath.Join(platform.DefaultDirs().Config, platform.HostIDFileName)
}
