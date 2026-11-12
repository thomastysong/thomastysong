package engine

import (
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// First-seen features (C2 item 7). Before rule evaluation the engine asks
// the persistent Baseline whether the acting account has been seen with
// each egress host of the record, and with the MCP server definition the
// record calls, and sets:
//
//	net.host_first_seen    true when a host in net.host is new for the account
//	mcp.server_first_seen  true when the MCP server definition is new for it
//
// An MCP server is identified by its definition hash from the inventory
// (Asset.SHA256 of the mcp_server asset with the same owner, parent agent
// and name) when the scan reported one, else by its name, so a changed
// definition counts as new. On an activity record the feature means the
// account's first call to that definition; on an inventory record of an
// MCP server, the first time the scan found that definition for its owner.
// The two are remembered separately: a scan that reports a new definition
// does not make the first call to it look familiar.
//
// A first sighting also adds the label first_seen (net.host, mcp.server)
// to the record and counts in the heartbeat (baseline.first_seen_hosts,
// baseline.first_seen_mcp). The features exist only where the baseline
// outlives one record: the daemon (persistent file) and the detect and scan
// replays (in memory); a hook process sees one record, so it sets none.
// Rules that name the features are matched at run time; the rule linter
// learns the names from the features registry.
//
// Keys are digests in the baseline file (it never holds a host name), and a
// record contributes at most maxFirstSeenHosts hosts: a hostile record can
// only make hosts look new again (more attention, never less).

// Feature and label names.
const (
	FeatHostFirstSeen = "net.host_first_seen"
	FeatMCPFirstSeen  = "mcp.server_first_seen"
	LabelFirstSeen    = "first_seen"
)

const (
	maxFirstSeenHosts = 16
	maxMCPDefs        = 4096
)

type mcpDefKey struct{ owner, agent, server string }

func (p *Pipeline) firstSeenEnabled() bool { return p.mode != ModeHook && p.bl != nil }

// firstSeen sets the first-seen features of an activity record; pmu is held.
func (p *Pipeline) firstSeen(ev *event.Event) {
	if !p.firstSeenEnabled() || ev.Feat == nil {
		return
	}
	acct := userKey(ev.User)
	var seen []string
	if hosts, _ := ev.Feat["net.host"].([]string); len(hosts) > 0 {
		isNew := false
		for i, h := range hosts {
			if i >= maxFirstSeenHosts {
				break
			}
			if h = strings.ToLower(strings.TrimSpace(h)); h == "" {
				continue
			}
			if !p.bl.Seen("spoor/first_seen\x00net.host\x00" + acct + "\x00" + h) {
				isNew = true
			}
		}
		ev.Feat[FeatHostFirstSeen] = isNew
		if isNew {
			p.ctr.firstSeenHosts++
			seen = append(seen, "net.host")
		}
	}
	if t := ev.Tool; t != nil && t.Kind == event.ToolMCP && t.MCPServer != "" {
		agent := ""
		if ev.Agent != nil {
			agent = ev.Agent.ID
		}
		def := p.mcpDefs[mcpDefKey{acct, agent, t.MCPServer}]
		if def == "" {
			def = "name:" + t.MCPServer
		}
		if p.mcpFirstSeen(ev, "call", acct, def) {
			seen = append(seen, "mcp.server")
		}
	}
	p.labelFirstSeen(ev, seen)
}

// firstSeenAsset records an MCP server definition from the inventory and
// sets mcp.server_first_seen on the inventory record.
func (p *Pipeline) firstSeenAsset(ev *event.Event) {
	a := ev.Asset
	if a == nil || a.Kind != event.AssetMCPServer || a.Name == "" || a.SHA256 == "" || a.Change == event.ChangeRemoved {
		return
	}
	if len(p.mcpDefs) >= maxMCPDefs {
		clear(p.mcpDefs)
	}
	p.mcpDefs[mcpDefKey{a.Owner, a.Parent, a.Name}] = "sha256:" + strings.ToLower(a.SHA256)
	if !p.firstSeenEnabled() || ev.Feat == nil {
		return
	}
	if p.mcpFirstSeen(ev, "definition", a.Owner, "sha256:"+strings.ToLower(a.SHA256)) {
		p.labelFirstSeen(ev, []string{"mcp.server"})
	}
}

func (p *Pipeline) mcpFirstSeen(ev *event.Event, what, acct, def string) bool {
	isNew := !p.bl.Seen("spoor/first_seen\x00mcp.server." + what + "\x00" + acct + "\x00" + def)
	ev.Feat[FeatMCPFirstSeen] = isNew
	if isNew {
		p.ctr.firstSeenMCP++
	}
	return isNew
}

func (p *Pipeline) labelFirstSeen(ev *event.Event, seen []string) {
	if len(seen) == 0 {
		return
	}
	l := make(map[string]string, len(ev.Labels)+1)
	for k, v := range ev.Labels {
		l[k] = v
	}
	l[LabelFirstSeen] = strings.Join(seen, ",")
	ev.Labels = l
}
