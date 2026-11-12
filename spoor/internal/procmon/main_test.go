package procmon

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// helperEnv turns the test binary into a helper process instead of running
// the tests:
//
//   - "hook": stands in for `spoor hook ...` (the binary is this package's
//     own test binary, so its file identity is the monitor's /proc/self/exe)
//     and idles for a minute (the test kills it sooner);
//   - "readability": runs one full scan of the real process table and
//     prints the readability counts as JSON (run as another account by the
//     live tests).
const helperEnv = "SPOOR_PROCMON_TEST_HELPER"

type readabilityReport struct {
	Total, Unreadable, Hidden, Protected uint64
	Euid                                 int
}

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "hook":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "readability":
		mon := New(Options{NoOsquery: true})
		mon.fullScan(time.Now())
		st := mon.Stats()
		_ = json.NewEncoder(os.Stdout).Encode(readabilityReport{Total: st.ProcsTotal, Unreadable: st.ProcsUnreadable,
			Hidden: st.ProcsHidden, Protected: st.ProcsProtected, Euid: os.Geteuid()})
		os.Exit(0)
	}
	os.Exit(m.Run())
}
