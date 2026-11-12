package shellx

import "strings"

var dockerGlobalSpec = &optSpec{
	short: "cHl",
	long:  longSet("--config", "--context", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey", "--url", "--connection", "--namespace", "--address"),
}

var dockerRunSpec = &optSpec{
	short: "aceghlmpuvw",
	long: longSet("--add-host", "--annotation", "--attach", "--blkio-weight", "--cap-add", "--cap-drop",
		"--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-shares", "--cpus",
		"--cpuset-cpus", "--cpuset-mems", "--device", "--dns", "--dns-option", "--dns-search", "--domainname",
		"--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
		"--health-interval", "--health-retries", "--health-timeout", "--hostname", "--ip", "--ip6", "--ipc",
		"--isolation", "--label", "--label-file", "--link", "--log-driver", "--log-opt", "--mac-address",
		"--memory", "--memory-reservation", "--memory-swap", "--mount", "--name", "--network", "--net",
		"--network-alias", "--pid", "--pids-limit", "--platform", "--publish", "--pull", "--restart", "--runtime",
		"--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs",
		"--ulimit", "--user", "--userns", "--uts", "--volume", "--volumes-from", "--workdir", "--detach-keys"),
	posStop: true,
}

var dockerExecSpec = &optSpec{
	short:   "euw",
	long:    longSet("--env", "--env-file", "--user", "--workdir", "--detach-keys"),
	posStop: true,
}

var composeSpec = &optSpec{
	short: "fp",
	long:  longSet("--file", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi", "--parallel", "--progress"),
}

// wrapDocker handles docker/podman/nerdctl: the command run inside a
// container, the flags that give a container host-level power, and the
// destructive prune family.
func wrapDocker(a *analyzer, c *simple, in flow) (flow, int) {
	sub, rest := subcommand(c.rest(), dockerGlobalSpec)
	if sub == "container" || sub == "image" || sub == "volume" || sub == "system" || sub == "builder" || sub == "network" {
		group := sub
		sub, rest = subcommand(rest, nil)
		switch group + " " + sub {
		case "system prune":
			a.dockerPrune(rest)
			return noFlow(), wrapNone
		case "volume prune":
			a.destructive("docker_prune_all")
			return noFlow(), wrapNone
		case "image prune", "builder prune", "container prune", "network prune":
			a.dockerPrune(rest)
			return noFlow(), wrapNone
		case "volume rm", "image rm":
			sub = "rm"
		}
		if group != "container" && sub != "rm" {
			return noFlow(), wrapNone
		}
	}
	switch sub {
	case "run", "create":
		o := parseOpts(rest, dockerRunSpec)
		a.dockerRunFacts(&o)
		if o.has("-d", "--detach") {
			a.f.Background = true
		}
		if len(o.pos) > 1 {
			return a.runInner(c, o.pos[1:], in, true, false), wrapDelegated
		}
		if ep, ok := o.get("--entrypoint"); ok && ep.s != "" {
			return a.runInner(c, []arg{ep}, in, true, false), wrapDelegated
		}
	case "exec":
		o := parseOpts(rest, dockerExecSpec)
		if o.has("--privileged") {
			a.priv("docker_privileged")
		}
		if len(o.pos) > 1 {
			return a.runInner(c, o.pos[1:], in, true, false), wrapDelegated
		}
	case "compose":
		csub, crest := subcommand(rest, composeSpec)
		switch csub {
		case "exec", "run":
			o := parseOpts(crest, dockerRunSpec)
			a.dockerRunFacts(&o)
			if len(o.pos) > 1 {
				return a.runInner(c, o.pos[1:], in, true, false), wrapDelegated
			}
		case "down":
			for _, r := range crest {
				if r.s == "-v" || r.s == "--volumes" {
					a.destructive("docker_prune_all")
				}
			}
		}
	case "rm", "rmi", "kill", "stop":
		// "docker rm -f $(docker ps -aq)" removes every container.
		for _, r := range rest {
			if r.dyn && strings.Contains(r.s, "$(") && sub != "kill" && sub != "stop" {
				a.destructive("docker_prune_all")
			}
		}
	case "prune":
		a.dockerPrune(rest)
	case "cp":
		// docker cp SRC DEST: a "container:path" side is not a local file.
		pos := positionalsOf(rest)
		if len(pos) == 2 {
			if !strings.Contains(pos[0].s, ":") {
				a.read(pos[0].s)
			}
			if !strings.Contains(pos[1].s, ":") {
				a.write(pos[1].s)
			}
		}
	}
	return noFlow(), wrapNone
}

func positionalsOf(args []arg) []arg {
	var out []arg
	for _, r := range args {
		if !strings.HasPrefix(r.s, "-") {
			out = append(out, r)
		}
	}
	return out
}

// dockerPrune flags prune variants that remove more than dangling objects.
func (a *analyzer) dockerPrune(rest []arg) {
	all := false
	for _, r := range rest {
		s := r.s
		if s == "--all" || s == "--volumes" || (len(s) > 1 && s[0] == '-' && s[1] != '-' && strings.ContainsRune(s, 'a')) {
			all = true
		}
	}
	if all {
		a.destructive("docker_prune_all")
	}
}

func (a *analyzer) dockerRunFacts(o *opts) {
	if o.has("--privileged") {
		a.priv("docker_privileged")
	}
	if o.has("--cap-add") {
		a.priv("cap_add")
	}
	for _, v := range o.all("--pid", "--userns", "--ipc", "--uts") {
		if v.s == "host" {
			a.priv("docker_privileged")
		}
	}
	for _, v := range o.all("--security-opt") {
		if strings.Contains(v.s, "unconfined") || strings.Contains(v.s, "disable") {
			a.priv("docker_privileged")
		}
	}
	for _, v := range o.all("-v", "--volume", "--mount", "--device") {
		l := strings.ToLower(v.s)
		if strings.Contains(l, "docker.sock") || strings.Contains(l, "containerd.sock") || strings.Contains(l, "crio.sock") || strings.Contains(l, "podman.sock") {
			a.priv("docker_socket_mount")
		}
		// Mounting the host root gives the container the whole machine.
		if strings.HasPrefix(l, "/:") || strings.Contains(l, "source=/,") || strings.Contains(l, "src=/,") {
			a.priv("docker_privileged")
		}
		if src := volumeSource(v.s); src != "" {
			a.read(src)
		}
	}
	for _, v := range o.all("--env-file") {
		a.read(v.s)
	}
}

// volumeSource returns the host path of a -v/--mount value when it is one.
func volumeSource(v string) string {
	if strings.Contains(v, "=") {
		for _, kv := range strings.Split(v, ",") {
			if strings.HasPrefix(kv, "source=") {
				return kv[len("source="):]
			}
			if strings.HasPrefix(kv, "src=") {
				return kv[len("src="):]
			}
		}
		return ""
	}
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return ""
	}
	src := v[:i]
	if strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") || strings.HasPrefix(src, "$") || strings.HasPrefix(src, ".") {
		return src
	}
	return ""
}

var kubectlSpec = &optSpec{
	short: "nsv",
	long: longSet("--namespace", "--context", "--cluster", "--user", "--kubeconfig", "--server", "--token",
		"--as", "--as-group", "--as-uid", "--certificate-authority", "--client-certificate", "--client-key",
		"--request-timeout", "--cache-dir", "--tls-server-name", "--password", "--username", "--profile",
		"--profile-output", "--log-flush-frequency", "--disable-compression"),
}

// wrapKubectl handles kubectl and oc: exec into a pod, deletes, secret reads
// and identity lookups.
func wrapKubectl(a *analyzer, c *simple, in flow) (flow, int) {
	sub, rest := subcommand(c.rest(), kubectlSpec)
	switch sub {
	case "exec", "debug":
		for i := range rest {
			if rest[i].s == "--" {
				if i+1 < len(rest) {
					return a.runInner(c, rest[i+1:], in, true, false), wrapDelegated
				}
				return noFlow(), wrapNone
			}
		}
		o := parseOpts(rest, &optSpec{short: "cnf", long: longSet("--container", "--namespace", "--filename", "--pod-running-timeout", "--image", "--target"), posStop: true})
		if len(o.pos) > 1 {
			return a.runInner(c, o.pos[1:], in, true, false), wrapDelegated
		}
	case "run":
		for i := range rest {
			if rest[i].s == "--" && i+1 < len(rest) {
				return a.runInner(c, rest[i+1:], in, true, false), wrapDelegated
			}
		}
	case "delete":
		kind := ""
		for _, r := range rest {
			if strings.HasPrefix(r.s, "-") {
				continue
			}
			kind = strings.ToLower(r.s)
			break
		}
		if i := strings.IndexByte(kind, '/'); i > 0 {
			kind = kind[:i]
		}
		switch kind {
		case "ns", "namespace", "namespaces":
			a.destructive("kubectl_delete_namespace")
		default:
			a.destructive("kubectl_delete")
		}
	case "drain":
		a.destructive("kubectl_delete")
	case "get", "describe":
		kind := ""
		for _, r := range rest {
			if !strings.HasPrefix(r.s, "-") {
				kind = strings.ToLower(r.s)
				break
			}
		}
		if i := strings.IndexByte(kind, '/'); i > 0 {
			kind = kind[:i]
		}
		if kind == "secret" || kind == "secrets" {
			// Listing names is routine; asking for the content is a read.
			for _, r := range rest {
				s := r.s
				if s == "-A" || s == "--all-namespaces" || strings.HasPrefix(s, "-o") || strings.HasPrefix(s, "--output") {
					a.cred("password_store")
				}
			}
		}
	case "config":
		csub, crest := subcommand(rest, nil)
		switch csub {
		case "view":
			for _, r := range crest {
				if r.s == "--raw" || r.s == "--flatten" {
					a.cred("token_print")
				}
			}
		case "current-context", "get-contexts", "get-clusters", "get-users":
			a.recon("cloud_identity")
		}
	case "create":
		if s, _ := subcommand(rest, nil); s == "token" {
			a.cred("token_print")
		}
	case "auth":
		if s, _ := subcommand(rest, nil); s == "whoami" || s == "can-i" {
			a.recon("cloud_identity")
		}
	case "cp":
		pos := positionalsOf(rest)
		if len(pos) == 2 {
			if !strings.Contains(pos[0].s, ":") {
				a.read(pos[0].s)
			}
			if !strings.Contains(pos[1].s, ":") {
				a.write(pos[1].s)
			}
		}
	}
	return noFlow(), wrapNone
}
