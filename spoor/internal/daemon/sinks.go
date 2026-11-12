package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/sink"
)

// openSinks opens the outbox (segment files, plus stdout when configured),
// the local ring, the optional network shippers and the outbox pruner.
func (d *daemon) openSinks() error {
	cfg := d.cfg
	files, err := sink.NewFiles(sink.FilesOptions{
		Dir:        d.layout.outbox,
		MaxSegment: cfg.Output.MaxSegment,
		// The daemon prunes the outbox itself, knowing what the shipper has
		// read (outbox.go); the sink's blind retention would delete unread
		// segments while Fluent Bit lags.
		RetainBytes:  -1,
		RetainAge:    -1,
		MaxLineBytes: cfg.Output.MaxLine,
		FileMode:     0o640,
		Format:       cfg.Output.Format,
		Now:          d.env.now,
	})
	if err != nil {
		return fmt.Errorf("daemon: outbox: %w", err)
	}
	d.files = files
	d.outbox = files
	if cfg.Output.Stdout {
		d.outbox = &teeSink{
			primary: files,
			mirrors: []sink.Sink{sink.NewStdout(d.env.stdout, cfg.Output.Format)},
			onMirrorError: func(name string, err error) {
				d.board.add("output."+name+"_errors", 1)
			},
		}
	}
	local, err := sink.NewFiles(sink.FilesOptions{
		Dir:          d.layout.local,
		MaxSegment:   cfg.Output.MaxSegment,
		RetainBytes:  cfg.Retention.LocalBytes,
		RetainAge:    cfg.Retention.Local.D(),
		MaxLineBytes: cfg.Output.MaxLine,
		FileMode:     0o600,
		Format:       sink.FormatNative,
		Now:          d.env.now,
	})
	if err != nil {
		return fmt.Errorf("daemon: local ring: %w", err)
	}
	d.local = local

	if f := cfg.Output.Forward; f != nil && f.Addr != "" {
		dst, err := sink.NewForward(sink.ForwardOptions{
			Addr: f.Addr, TagPrefix: f.TagPrefix, SharedKey: f.SharedKey,
			Compress: f.Compress, Timeout: f.Timeout.D(),
		})
		if err != nil {
			return fmt.Errorf("daemon: output.forward: %w", err)
		}
		d.shippers = append(d.shippers, d.newShipper("forward", dst))
	}
	if o := cfg.Output.OTLP; o != nil && o.Endpoint != "" {
		dst, err := sink.NewOTLP(sink.OTLPOptions{
			Endpoint: o.Endpoint, Headers: o.Headers, Gzip: o.Gzip,
			Timeout: o.Timeout.D(), ServiceVersion: Version,
		})
		if err != nil {
			return fmt.Errorf("daemon: output.otlp: %w", err)
		}
		d.shippers = append(d.shippers, d.newShipper("otlp", dst))
	}

	tailSpec, check := cfg.Output.FluentBit.TailDB, d.layout.check
	var shipCons []consumer
	for _, s := range d.shippers {
		shipCons = append(shipCons, &shipperConsumer{name: s.name, path: s.checkpoint})
	}
	consumers := func() []consumer {
		return append(tailDBConsumers(tailSpec, check), shipCons...)
	}
	d.pruner = newOutboxPruner(pruneOptions{
		dir:       d.layout.outbox,
		maxAge:    cfg.Retention.Outbox.D(),
		maxBytes:  cfg.Retention.OutboxBytes,
		consumers: consumers,
		statePath: filepath.Join(d.layout.check, "outbox-consumers.json"),
	})
	return nil
}

// shipperRun is one optional network shipper over the outbox.
type shipperRun struct {
	name       string
	checkpoint string
	dst        sink.Sink
	sh         *sink.Shipper
}

func (d *daemon) newShipper(name string, dst sink.Sink) *shipperRun {
	cp := filepath.Join(d.layout.check, "shipper-"+name+".checkpoint")
	return &shipperRun{
		name:       name,
		checkpoint: cp,
		dst:        dst,
		sh:         sink.NewShipper(sink.ShipperOptions{Dir: d.layout.outbox, Checkpoint: cp}, dst),
	}
}

func (s *shipperRun) run(ctx context.Context, d *daemon) {
	defer func() {
		if r := recover(); r != nil {
			d.board.add("daemon.panics", 1)
			d.log.Error("shipper stopped after a panic", "shipper", s.name, "panic", fmt.Sprint(r))
		}
	}()
	if err := s.sh.Run(ctx); err != nil {
		d.log.Error("shipper cannot run", "shipper", s.name, "error", err)
	}
}

// report copies the shipper's counters into the heartbeat. The text of the
// last error is not copied: it can quote a server's reply.
func (s *shipperRun) report(b *board) {
	st := s.sh.Stats()
	pre := "shipper." + s.name + "."
	b.set(pre+"shipped", st.Shipped)
	b.set(pre+"dropped", st.Dropped)
	b.set(pre+"errors", st.Errors)
	b.set(pre+"bad_lines", st.BadLines)
	if st.Backlog >= 0 {
		b.set(pre+"backlog_bytes", uint64(st.Backlog))
	}
}

// teeSink writes every batch to the outbox files (primary) and to mirrors
// (stdout). The pipeline counts a batch whose write failed as dropped
// (outbox.dropped, the state database's dropped column), so only the
// primary's result is the batch's result: a mirror that fails (stdout
// closed by the service manager) is counted through onMirrorError, while
// the records are still in the outbox for Fluent Bit.
type teeSink struct {
	primary       sink.Sink
	mirrors       []sink.Sink
	onMirrorError func(name string, err error) // nil: ignore
}

func (t *teeSink) Name() string { return "tee" }

func (t *teeSink) mirrorFailed(s sink.Sink, err error) {
	if t.onMirrorError != nil {
		t.onMirrorError(s.Name(), err)
	}
}

func (t *teeSink) Write(batch []*event.Event) error {
	err := t.primary.Write(batch)
	for _, m := range t.mirrors {
		if merr := m.Write(batch); merr != nil {
			t.mirrorFailed(m, merr)
		}
	}
	return err
}

func (t *teeSink) Flush() error {
	err := t.primary.Flush()
	for _, m := range t.mirrors {
		if merr := m.Flush(); merr != nil {
			t.mirrorFailed(m, merr)
		}
	}
	return err
}

func (t *teeSink) Close() error {
	err := t.primary.Close()
	for _, m := range t.mirrors {
		if merr := m.Close(); merr != nil && !errors.Is(merr, sink.ErrClosed) {
			t.mirrorFailed(m, merr)
		}
	}
	return err
}
