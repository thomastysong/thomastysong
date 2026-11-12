package transcript

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// ReadFile parses one session log completely, without checkpoints. It
// applies the same rules as the Tailer: no symlinks, regular files only,
// complete lines only, compressed rollouts and single-document sessions
// handled by format. maxLine <= 0 selects the default.
func ReadFile(path string, parser Parser, user event.User, maxLine int) ([]*event.Event, *FileState, error) {
	return ReadFileRewrite(path, parser, user, maxLine, nil)
}

// ReadFileRewrite is ReadFile with every line (every document, for
// single-document formats) passed through rewrite before it is parsed;
// the line-size limit applies to the line as read. internal/bench uses it
// to replay logs recorded before the project was renamed. A nil rewrite
// is ReadFile.
func ReadFileRewrite(path string, parser Parser, user event.User, maxLine int, rewrite func(line []byte) []byte) ([]*event.Event, *FileState, error) {
	if parser == nil {
		var ok bool
		if parser, ok = ForPath(path); !ok {
			return nil, nil, fmt.Errorf("transcript: no parser matches %s", path)
		}
	}
	if maxLine <= 0 {
		maxLine = defaultMaxLine
	}
	// The path is taken literally (no glob expansion): its directory is the
	// trusted base and the file name is opened without following a link.
	clean := filepath.Clean(path)
	f, meta, err := openBeneath(filepath.Dir(clean), filepath.Base(clean))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if !ownerOK(meta, user.ID) {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: errors.New("file is not owned by the expected user")}
	}
	c := candidate{path: clean}
	st := &FileState{Path: c.path, user: &user}
	var evs []*event.Event
	collect := func(line []byte) {
		if rewrite != nil {
			line = rewrite(line)
		}
		out, _ := parser.ParseLine(line, st)
		evs = append(evs, out...)
	}
	never := func() bool { return false }
	switch modeOf(parser, c.path) {
	case modeZstd:
		n, rerr := readZstdLines(f, maxLine, never, collect)
		st.Oversize += n
		err = rerr
	case modeDocument:
		var b []byte
		if b, err = readDocument(f, meta.size); err == nil {
			collect(b)
		}
	default:
		budget := int64(1) << 62
		var res readResult
		res, err = readLines(f, 0, meta.size, maxLine, false, &budget, never, collect)
		st.Oversize += res.oversize
	}
	return evs, st, err
}
