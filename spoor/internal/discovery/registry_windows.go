//go:build windows

package discovery

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// winInstall is one Windows Uninstall registry entry.
type winInstall struct{ display, version, location string }

const maxUninstallKeys = 4096

// uninstallPaths are read under HKLM (both registry views) and under the
// user's hive. Values are read as strings only; nothing is executed.
var uninstallPaths = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// windowsInstalls lists Uninstall entries: HKLM for sid "", else the hive
// HKU\<sid> (loaded only while the user is logged on; an unloaded hive is
// simply absent and reported as nothing found).
//
// UNVERIFIED: compiled for windows, not executed in the build environment.
func windowsInstalls(sid string) (out []winInstall) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	root := registry.LOCAL_MACHINE
	prefix := ""
	if sid != "" {
		if !validSID(sid) {
			return nil
		}
		root = registry.USERS
		prefix = sid + `\`
	}
	for _, p := range uninstallPaths {
		k, err := registry.OpenKey(root, prefix+p, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(maxUninstallKeys)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			d, _, _ := sk.GetStringValue("DisplayName")
			v, _, _ := sk.GetStringValue("DisplayVersion")
			l, _, _ := sk.GetStringValue("InstallLocation")
			sk.Close()
			if d != "" && len(d) < 512 {
				out = append(out, winInstall{display: d, version: v, location: l})
			}
		}
		k.Close()
	}
	return out
}

func validSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 184 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '-' || c == 'S') {
			return false
		}
	}
	return true
}

// registryProbe reports whether HKLM\<key> exists and, when value is not
// "" or "*", whether it holds that value.
func registryProbe(key, value string) (exists, ok bool) {
	defer func() {
		if recover() != nil {
			exists, ok = false, true
		}
	}()
	key = strings.TrimPrefix(strings.TrimPrefix(key, `HKLM\`), `HKEY_LOCAL_MACHINE\`)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false, true
	}
	defer k.Close()
	if value == "" || value == "*" {
		return true, true
	}
	_, _, err = k.GetValue(value, nil)
	return err == nil, true
}
