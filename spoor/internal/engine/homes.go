package engine

import (
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

// homeCache answers "what is this account's home directory" for feature
// computation (path classes relative to the acting user's home) and for the
// privacy stage's "~/..." rewriting. A daemon serves every account on the
// host, so one engine-wide home would classify other users' credential
// paths as ordinary files. The account list is read at most once a minute
// and only when an unknown account shows up.
type homeCache struct {
	mu     sync.Mutex
	custom func(uid, name string) string
	byUID  map[string]string
	byName map[string]string
	loaded time.Time
}

const homeRefresh = time.Minute

func newHomeCache(custom func(uid, name string) string) *homeCache {
	return &homeCache{custom: custom}
}

func (h *homeCache) home(uid, name string, now time.Time) string {
	if uid == "" && name == "" {
		return ""
	}
	if h.custom != nil {
		return h.custom(uid, name)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if v := h.lookup(uid, name); v != "" {
		return v
	}
	if !h.loaded.IsZero() && now.Sub(h.loaded) < homeRefresh {
		return ""
	}
	h.loaded = now
	users, err := platform.Users()
	if err != nil && len(users) == 0 {
		return ""
	}
	h.byUID = make(map[string]string, len(users))
	h.byName = make(map[string]string, len(users))
	for i, u := range users {
		if i >= 10000 {
			break
		}
		// Users lists the account database entry first; a second entry
		// for the same account ($HOME override) must not replace it.
		if _, ok := h.byUID[u.UID]; !ok && u.UID != "" {
			h.byUID[u.UID] = u.Home
		}
		if _, ok := h.byName[u.Name]; !ok && u.Name != "" {
			h.byName[u.Name] = u.Home
		}
	}
	return h.lookup(uid, name)
}

func (h *homeCache) lookup(uid, name string) string {
	if uid != "" {
		if v, ok := h.byUID[uid]; ok {
			return v
		}
	}
	if name != "" {
		if v, ok := h.byName[name]; ok {
			return v
		}
	}
	return ""
}
