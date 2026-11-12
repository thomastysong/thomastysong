package procmon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func TestZZSmoke(t *testing.T) {
	if os.Getenv("SMOKE") == "" {
		t.Skip()
	}
	var mu sync.Mutex
	var evs []*event.Event
	m := New(Options{ExecEvents: true, NoOsquery: true, Emit: func(e *event.Event) { mu.Lock(); evs = append(evs, e); mu.Unlock() }})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() { time.Sleep(1500 * time.Millisecond); fmt.Println("source", m.Source()) }()
	start := time.Now()
	_ = m.Run(ctx)
	fmt.Println("ran", time.Since(start), "source", m.Source(), "stats", fmt.Sprintf("%+v", m.Stats()))
	for _, a := range m.Agents() {
		b, _ := json.Marshal(a)
		fmt.Println("agent", string(b))
	}
	mu.Lock()
	for i, e := range evs {
		if i > 30 {
			break
		}
		b, _ := e.MarshalLine()
		fmt.Print(string(b))
	}
	fmt.Println("events", len(evs))
	mu.Unlock()
}
