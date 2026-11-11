// Package deps pins the module's third-party dependencies during the build-out
// so parallel work never needs to touch go.mod. It is removed before release.
package deps

import (
	_ "github.com/BurntSushi/toml"
	_ "github.com/klauspost/compress/zstd"
	_ "github.com/osquery/osquery-go"
	_ "github.com/osquery/osquery-go/plugin/table"
	_ "golang.org/x/sys/cpu"
	_ "golang.org/x/text/encoding/unicode"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
	_ "mvdan.cc/sh/v3/syntax"
)
