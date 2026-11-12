package osqexec

import (
	"context"
	"time"

	osquery "github.com/osquery/osquery-go"
)

// querier is the part of the osquery extension-manager client this package
// uses. It exists so the logic can be tested without an osqueryd.
type querier interface {
	QueryRowsContext(ctx context.Context, sql string) ([]map[string]string, error)
	Close()
}

type dialFunc func(path string, timeout time.Duration) (querier, error)

// dialOsquery connects with the osquery-go Thrift client. The timeout is the
// connect timeout and the socket read tick.
func dialOsquery(path string, timeout time.Duration) (querier, error) {
	c, err := osquery.NewClient(path, timeout)
	if err != nil {
		return nil, err
	}
	return c, nil
}
