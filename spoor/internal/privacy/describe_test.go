package privacy

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	for _, p := range []*Policy{
		nil,
		{},
		{Profile: ProfileStandard, Key: testKey, KeyID: "tenant-1"},
		{Profile: ProfileFull, Key: testKey, PseudonymizeUsers: true, Exclude: Exclusions{Paths: []string{"~/private/**"}, Repos: []string{"github.com/me/*"}, Users: []string{"svc-*"}}},
		{PseudonymizeUsers: true},
	} {
		lines := p.Describe()
		all := strings.Join(lines, "\n")
		if len(lines) < 6 {
			t.Errorf("too short: %q", all)
		}
		prof := ProfileMinimal
		if p != nil && p.Profile != "" {
			prof = p.Profile
		}
		if !strings.Contains(all, "Privacy profile: "+string(prof)) {
			t.Errorf("profile not stated:\n%s", all)
		}
		if !strings.Contains(all, "Never leaves this machine") || strings.Contains(all, "files the agent writes with its file tools") == (prof == ProfileFull) {
			t.Errorf("never-leaves line missing:\n%s", all)
		}
		// Review P5: shell-written file text is part of the command and
		// does ship (redacted) outside full; Describe must say so rather
		// than promise that file contents never leave.
		if strings.Contains(all, "file contents being written") {
			t.Errorf("claims file contents never leave, but shell-written text is part of a command:\n%s", all)
		}
		if prof != ProfileFull && !strings.Contains(all, "Text a shell command writes into a file") {
			t.Errorf("shell-written file text not explained:\n%s", all)
		}
		hasKey := p != nil && len(p.Key) >= MinKeyLen
		if hasKey != strings.Contains(all, "Limit of the key") {
			t.Errorf("key limit statement (key=%v):\n%s", hasKey, all)
		}
		if p != nil && len(p.Exclude.Paths) > 0 && !strings.Contains(all, "~/private/**") {
			t.Errorf("exclusions not listed:\n%s", all)
		}
		if p != nil && p.PseudonymizeUsers && !hasKey && !strings.Contains(all, "removed instead") {
			t.Errorf("pseudonym without key not explained:\n%s", all)
		}
		if strings.Contains(all, string(testKey)) {
			t.Error("Describe must never print the key")
		}
	}
}
