package shellx

import "strings"

func registerDev() {
	register(hGit, "git")
	register(hGh, "gh", "glab")
	register(hTerraform, "terraform", "tofu", "terragrunt", "pulumi", "cdk", "cdktf")
	register(hAws, "aws", "aws2")
	register(hGcloud, "gcloud", "gsutil", "bq")
	register(hAz, "az", "azcopy")
	register(hCloudMisc, "doctl", "heroku", "fly", "flyctl", "vercel", "railway", "oci", "s3cmd", "rclone", "mc", "b2", "s5cmd", "helm", "supabase", "netlify", "wrangler")
	register(hDB, "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "redis-cli", "clickhouse-client",
		"cockroach", "duckdb", "snowsql", "cqlsh", "dropdb", "mysqladmin", "pg_dump", "pg_dumpall", "mysqldump", "mongodump")
	register(hAppFramework, "rails", "rake", "prisma", "manage.py", "django-admin", "artisan", "alembic", "flyway", "knex", "sequelize")
	register(hPasswordStore, "pass", "gopass", "bw", "lpass", "keepassxc-cli", "vault", "sops", "ansible-vault", "chamber", "infisical", "doppler", "op")
	register(hTokenTools, "docker-credential-desktop", "docker-credential-osxkeychain", "docker-credential-pass",
		"docker-credential-secretservice", "docker-credential-wincred", "docker-credential-ecr-login", "docker-credential-gcloud",
		"git-credential-osxkeychain", "git-credential-manager", "git-credential-manager-core", "git-credential-libsecret", "firebase")
	register(hSecretScanners, "trufflehog", "gitleaks", "detect-secrets", "ggshield", "linpeas", "linpeas.sh", "lazagne", "mimikatz", "secretsdump", "pypykatz")
	register(hBfg, "bfg", "git-filter-repo")
}

var gitGlobalSpec = &optSpec{short: "Cc", long: longSet{"--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix", "--config-env", "--attr-source"}}

// gitConfigFacts classifies one "key=value" or key/value git config setting.
func (a *analyzer) gitConfigFacts(key, val string, depth int) {
	k := strings.ToLower(key)
	switch {
	case strings.HasPrefix(k, "credential."), strings.HasSuffix(k, ".insteadof"), strings.HasSuffix(k, ".pushinsteadof"),
		strings.HasSuffix(k, ".extraheader"), k == "core.sshcommand", k == "core.askpass":
		a.gitop("config_credential")
	case k == "core.hookspath", k == "init.templatedir":
		if val == "/dev/null" || val == "" || strings.EqualFold(val, "nul") {
			a.gitop("commit_no_verify")
		} else {
			a.persist("git_hook")
		}
	}
	// Config keys whose value git runs as a command (threats.md GIT_EXEC_KEYS).
	if val != "" && (k == "core.sshcommand" || k == "core.pager" || k == "core.editor" || k == "core.fsmonitor" ||
		k == "core.gitproxy" || k == "sequence.editor" || strings.HasSuffix(k, ".textconv") || strings.HasSuffix(k, ".command") ||
		strings.HasSuffix(k, ".clean") || strings.HasSuffix(k, ".smudge") || strings.HasSuffix(k, ".driver") ||
		strings.HasPrefix(k, "alias.") && strings.HasPrefix(val, "!")) {
		if val != "true" && val != "false" {
			a.sub(strings.TrimPrefix(val, "!"), Posix, OriginEval, depth+1, noFlow())
		}
	}
}

func hGit(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	// Global options, including -c key=value settings.
	for i := 0; i < len(args); i++ {
		if args[i].s == "-c" && i+1 < len(args) {
			if k, v, ok := strings.Cut(args[i+1].s, "="); ok {
				a.gitConfigFacts(k, v, c.depth)
			}
		}
	}
	for i := range c.env {
		if c.env[i].name == "HUSKY" && c.env[i].val.s == "0" {
			a.gitop("commit_no_verify")
		}
		if n := c.env[i].name; n == "GIT_SSH_COMMAND" || n == "GIT_EXTERNAL_DIFF" || n == "GIT_PAGER" || n == "GIT_EDITOR" || n == "GIT_ASKPASS" || n == "GIT_PROXY_COMMAND" {
			// Environment variables git runs as commands.
			if v := c.env[i].val.s; v != "" {
				a.sub(v, Posix, OriginEval, c.depth+1, noFlow())
			}
		}
	}
	sub, rest := subcommand(args, gitGlobalSpec)
	switch sub {
	case "push":
		a.gitop("push")
		o := parseOpts(rest, &optSpec{short: "o", long: longSet{"--repo", "--push-option", "--receive-pack", "--exec", "--force-with-lease", "--recurse-submodules"}})
		force := o.has("-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror")
		for i := range o.flags {
			if strings.HasPrefix(o.flags[i].name, "--force-with-lease") {
				force = true
			}
		}
		for i, p := range o.pos {
			if i >= 1 && strings.HasPrefix(p.s, "+") {
				force = true // +refspec
			}
		}
		if force {
			a.gitop("push_force")
			a.destructive("git_force_push")
		}
		if o.has("--no-verify") {
			a.gitop("commit_no_verify")
		}
		for _, v := range o.all("--receive-pack", "--exec") {
			a.sub(v.s, Posix, OriginWrapper, c.depth+1, noFlow())
		}
		if len(o.pos) > 0 {
			remote := o.pos[0].s
			if strings.Contains(remote, "://") || strings.Contains(remote, "@") && strings.Contains(remote, ":") {
				// Pushing to a URL instead of a configured remote.
				a.exfil("git_push_new_remote")
				a.gitRemoteHost(remote)
			} else {
				for _, r := range a.gitRemotes {
					if r == remote {
						a.exfil("git_push_new_remote")
					}
				}
			}
		} else if len(a.gitRemotes) > 0 {
			for _, r := range a.gitRemotes {
				if r == "origin" {
					a.exfil("git_push_new_remote")
				}
			}
		}
	case "remote":
		rsub, rrest := subcommand(rest, nil)
		pos := positionalsOf(rrest)
		switch rsub {
		case "add":
			a.gitop("remote_add")
			if len(pos) >= 2 {
				a.gitRemotes = append(a.gitRemotes, pos[0].s)
				a.gitRemoteHost(pos[1].s)
			}
		case "set-url":
			a.gitop("remote_add")
			if len(pos) >= 2 {
				a.gitRemotes = append(a.gitRemotes, pos[0].s)
				a.gitRemoteHost(pos[1].s)
			}
		}
	case "clone":
		a.gitop("clone")
		a.f.Downloads = true
		a.unpacked = true
		o := parseOpts(rest, &optSpec{short: "bcojuO", long: longSet{"--branch", "--config", "--origin", "--depth", "--jobs", "--upload-pack",
			"--reference", "--separate-git-dir", "--template", "--filter", "--shallow-since", "--shallow-exclude", "--recurse-submodules"}})
		if len(o.pos) > 0 {
			a.gitRemoteHost(o.pos[0].s)
		}
		for _, v := range o.all("-c", "--config") {
			if k, val, ok := strings.Cut(v.s, "="); ok {
				a.gitConfigFacts(k, val, c.depth)
			}
		}
		for _, v := range o.all("-u", "--upload-pack") {
			a.sub(v.s, Posix, OriginWrapper, c.depth+1, noFlow())
		}
	case "fetch", "pull", "ls-remote", "submodule":
		for _, r := range rest {
			if v, ok := strings.CutPrefix(r.s, "--upload-pack="); ok {
				a.sub(v, Posix, OriginWrapper, c.depth+1, noFlow())
			}
			if strings.Contains(r.s, "://") {
				a.gitRemoteHost(r.s)
			}
		}
	case "commit", "merge", "am", "cherry-pick", "revert":
		for _, r := range rest {
			if r.s == "--" {
				break
			}
			if r.s == "--no-verify" || sub == "commit" && commitShortNoVerify(r.s) {
				a.gitop("commit_no_verify")
			}
		}
	case "reset":
		for _, r := range rest {
			if r.s == "--hard" {
				a.destructive("git_reset_hard")
			}
		}
	case "checkout", "restore", "switch":
		discard := false
		for i, r := range rest {
			switch {
			case sub == "checkout" && (r.s == "-f" || r.s == "--force"):
				discard = true
			case sub == "switch" && (r.s == "--discard-changes" || r.s == "-f" || r.s == "--force"):
				discard = true
			case (r.s == "." || r.s == ":/" || r.s == "*") && (sub == "restore" || i == 0 || rest[i-1].s == "--"):
				// "git checkout -- ." and "git restore ." discard all edits.
				discard = true
			}
		}
		if sub == "restore" && containsArgFold(rest, "--staged") && !containsArgFold(rest, "--worktree") {
			discard = false // unstaging keeps the edits
		}
		if discard {
			a.destructive("git_reset_hard")
		}
	case "clean":
		force, dry := false, false
		for _, r := range rest {
			if len(r.s) >= 2 && r.s[0] == '-' && r.s[1] != '-' {
				if strings.ContainsRune(r.s, 'f') {
					force = true
				}
				if strings.ContainsRune(r.s, 'n') {
					dry = true
				}
			}
			if r.s == "--force" {
				force = true
			}
			if r.s == "--dry-run" {
				dry = true
			}
		}
		if force && !dry {
			a.destructive("git_clean_force")
		}
	case "filter-branch", "filter-repo":
		a.destructive("git_history_rewrite")
		for i, r := range rest {
			// --tree-filter CMD, --index-filter CMD ... run a shell command.
			if strings.HasSuffix(r.s, "-filter") && i+1 < len(rest) {
				a.sub(rest[i+1].s, Posix, OriginWrapper, c.depth+1, noFlow())
			}
		}
	case "rebase":
		for i, r := range rest {
			if r.s == "-i" || r.s == "--interactive" || r.s == "--root" {
				a.destructive("git_history_rewrite")
			}
			if (r.s == "-x" || r.s == "--exec") && i+1 < len(rest) {
				a.sub(rest[i+1].s, Posix, OriginWrapper, c.depth+1, noFlow())
			}
		}
	case "reflog":
		rsub, _ := subcommand(rest, nil)
		if rsub == "expire" || rsub == "delete" {
			a.destructive("git_history_rewrite")
		}
	case "update-ref":
		if containsArgFold(rest, "-d") {
			a.destructive("git_history_rewrite")
		}
	case "config":
		pos := positionalsOf(rest)
		unset := containsArgFold(rest, "--unset") || containsArgFold(rest, "--unset-all") || containsArgFold(rest, "--remove-section")
		list := containsArgFold(rest, "--list") || containsArgFold(rest, "-l") || containsArgFold(rest, "--get") || containsArgFold(rest, "--get-all")
		if len(pos) > 0 && (pos[0].s == "set" || pos[0].s == "get" || pos[0].s == "unset" || pos[0].s == "list") {
			if pos[0].s != "set" {
				list = true
			}
			pos = pos[1:]
		}
		if len(pos) >= 2 && !unset && !list {
			a.gitConfigFacts(pos[0].s, pos[1].s, c.depth)
		}
		if len(pos) >= 1 && list && strings.HasPrefix(strings.ToLower(pos[0].s), "credential") {
			a.gitop("config_credential")
		}
	case "credential", "credential-store", "credential-cache":
		a.gitop("config_credential")
		if rsub, _ := subcommand(rest, nil); rsub == "fill" || rsub == "get" {
			a.cred("token_print")
		}
	case "grep":
		for _, r := range positionalsOf(rest) {
			if secretPattern(r.s) {
				a.recon("find_secrets")
			}
			break
		}
	case "archive":
		for _, r := range rest {
			if v, ok := strings.CutPrefix(r.s, "--remote="); ok {
				a.gitRemoteHost(v)
			}
			if v, ok := strings.CutPrefix(r.s, "--exec="); ok {
				a.sub(v, Posix, OriginWrapper, c.depth+1, noFlow())
			}
		}
	}
}

// commitShortNoVerify reports "-n" in a git commit short-option cluster. A
// letter that takes a value (-m, -F ...) ends the cluster: what follows is
// that option's argument, not more flags.
func commitShortNoVerify(s string) bool {
	if len(s) < 2 || s[0] != '-' || s[1] == '-' {
		return false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case 'n':
			return true
		case 'm', 'F', 'C', 'c', 't', 'S', 'u':
			return false
		}
	}
	return false
}

// gitRemoteHost records the host of a git remote in either URL or scp form.
func (a *analyzer) gitRemoteHost(remote string) {
	if strings.Contains(remote, "://") {
		a.url(remote)
		return
	}
	if h, ok := remoteSpec(remote); ok {
		a.host(h)
	}
}

func hBfg(a *analyzer, c *simple, in flow, out *flow) {
	a.destructive("git_history_rewrite")
}

func hGh(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	sub, r1 := subcommand(rest, &optSpec{short: "R", long: longSet{"--repo", "--hostname"}})
	sub2, r2 := subcommand(r1, nil)
	switch sub + " " + sub2 {
	case "auth token":
		a.cred("token_print")
	case "auth status":
		a.recon("cloud_identity")
		for _, r := range r2 {
			if r.s == "--show-token" || r.s == "-t" {
				a.cred("token_print")
			}
		}
	case "repo clone":
		a.gitop("clone")
		a.f.Downloads = true
		a.unpacked = true
	case "repo delete", "release delete", "secret delete", "variable delete", "workflow disable", "run delete", "codespace delete", "gist delete":
		if sub2 == "delete" {
			a.destructive("cloud_delete")
		}
	case "gist create":
		// Publishing local files to a gist.
		a.exfil("paste_post")
		for _, p := range positionalsOf(r2) {
			if p.s != "-" {
				a.read(p.s)
			}
		}
	case "release download", "run download":
		a.f.Downloads = true
	case "secret list", "variable list":
		a.recon("cloud_identity")
	}
	if sub == "api" {
		a.ghAPI(r1)
	}
}

// ghAPI classifies "gh api" calls by method.
func (a *analyzer) ghAPI(rest []arg) {
	o := parseOpts(rest, &optSpec{short: "XfFHqt", long: longSet{"--method", "--field", "--raw-field", "--header", "--input", "--jq", "--template", "--hostname", "--cache"}})
	m, _ := o.get("-X", "--method")
	method := strings.ToUpper(m.s)
	if method == "DELETE" {
		a.destructive("cloud_delete")
	}
	if f, ok := o.get("--input"); ok && f.s != "-" {
		a.read(f.s)
	}
	if len(o.pos) > 0 {
		p := strings.ToLower(o.pos[0].s)
		if p == "user" || p == "/user" || strings.HasPrefix(p, "user/") || strings.HasPrefix(p, "/user/") {
			a.recon("cloud_identity")
		}
	}
}

func hTerraform(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	var sub string
	var after []arg
	switch c.name {
	case "terraform", "tofu", "terragrunt":
		sub, after = subcommand(rest, &optSpec{oneDash: true})
		if c.name == "terragrunt" && (sub == "run-all" || sub == "run") {
			sub, after = subcommand(after, &optSpec{oneDash: true})
		}
	default:
		sub, after = subcommand(rest, nil)
	}
	switch {
	case sub == "destroy" || sub == "down" && c.name == "pulumi":
		a.destructive("terraform_destroy")
	case sub == "apply":
		for _, r := range after {
			if r.s == "-destroy" || r.s == "--destroy" {
				a.destructive("terraform_destroy")
			}
		}
	case sub == "stack" && c.name == "pulumi":
		if s, r := subcommand(after, nil); s == "rm" {
			a.destructive("terraform_destroy")
		} else if s == "output" && containsArgFold(r, "--show-secrets") {
			a.cred("token_print")
		}
	}
}

// awsGlobalSpec lists aws global options that take a value.
var awsGlobalSpec = &optSpec{long: longSet{"--profile", "--region", "--output", "--endpoint-url", "--query", "--color",
	"--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format"}}

func hAws(a *analyzer, c *simple, in flow, out *flow) {
	svc, r1 := subcommand(c.rest(), awsGlobalSpec)
	op, r2 := subcommand(r1, awsGlobalSpec)
	switch svc {
	case "s3":
		pos := positionalsOf(r2)
		switch op {
		case "cp", "mv", "sync":
			if len(pos) >= 2 {
				src, dst := pos[0].s, pos[1].s
				srcRemote, dstRemote := strings.HasPrefix(src, "s3://"), strings.HasPrefix(dst, "s3://")
				if !srcRemote {
					a.read(src)
				}
				if dstRemote && !srcRemote {
					a.exfil("cloud_bucket_upload")
				}
				if srcRemote && !dstRemote {
					a.f.Downloads = true
					a.write(dst)
					a.drop(dst, tDownload)
				}
				if op == "sync" && dstRemote && containsArgFold(r2, "--delete") {
					a.destructive("cloud_delete")
				}
			}
		case "rb":
			a.destructive("cloud_delete")
		case "rm":
			if containsArgFold(r2, "--recursive") {
				a.destructive("cloud_delete")
			}
		}
	case "s3api":
		if op == "put-object" {
			a.exfil("cloud_bucket_upload")
			for i, r := range r2 {
				if r.s == "--body" && i+1 < len(r2) {
					a.read(r2[i+1].s)
				}
			}
		}
	case "sts":
		switch op {
		case "get-caller-identity":
			a.recon("cloud_identity")
		case "get-session-token", "assume-role", "assume-role-with-web-identity", "get-federation-token":
			a.cred("token_print")
		}
	case "configure":
		switch op {
		case "export-credentials":
			a.cred("token_print")
		case "get":
			for _, p := range positionalsOf(r2) {
				l := strings.ToLower(p.s)
				if strings.Contains(l, "secret") || strings.Contains(l, "token") || strings.Contains(l, "access_key") {
					a.cred("token_print")
				}
			}
		case "list", "list-profiles":
			a.recon("cloud_identity")
		}
	case "secretsmanager":
		if op == "get-secret-value" || op == "batch-get-secret-value" {
			a.cred("password_store")
		}
	case "ssm":
		if strings.HasPrefix(op, "get-parameter") && containsArgFold(r2, "--with-decryption") {
			a.cred("password_store")
		}
	case "ecr", "ecr-public":
		if op == "get-login-password" || op == "get-authorization-token" {
			a.cred("token_print")
		}
	case "codeartifact":
		if op == "get-authorization-token" {
			a.cred("token_print")
		}
	case "iam":
		switch op {
		case "get-user", "list-users", "list-roles", "get-account-authorization-details", "list-attached-user-policies", "get-account-summary":
			a.recon("cloud_identity")
		case "create-access-key":
			a.cred("token_print")
		}
	}
	if strings.HasPrefix(op, "delete-") || strings.HasPrefix(op, "terminate-") || strings.HasPrefix(op, "destroy-") ||
		strings.HasPrefix(op, "deregister-") || op == "purge-queue" || strings.HasPrefix(op, "batch-delete-") {
		a.destructive("cloud_delete")
	}
}

func hGcloud(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	pos := positionalsOf(rest)
	words := strs(pos)
	joined := " " + strings.ToLower(strings.Join(words, " ")) + " "
	switch c.name {
	case "gsutil":
		// gsutil [-m] cp|mv|rsync|rm|rb ...
		var op string
		var args []arg
		for i, p := range pos {
			switch p.s {
			case "cp", "mv", "rsync", "rm", "rb", "cat":
				op, args = p.s, pos[i+1:]
			}
			if op != "" {
				break
			}
		}
		switch op {
		case "cp", "mv", "rsync":
			if len(args) >= 2 {
				src, dst := args[0].s, args[len(args)-1].s
				if !strings.HasPrefix(src, "gs://") {
					a.read(src)
					if strings.HasPrefix(dst, "gs://") {
						a.exfil("cloud_bucket_upload")
					}
				} else if !strings.HasPrefix(dst, "gs://") {
					a.f.Downloads = true
					a.write(dst)
					a.drop(dst, tDownload)
				}
			}
		case "rb":
			a.destructive("cloud_delete")
		case "rm":
			if c.hasShort('r') || c.hasShort('a') {
				a.destructive("cloud_delete")
			}
		}
		return
	case "bq":
		if strings.Contains(joined, " rm ") {
			a.destructive("cloud_delete")
		}
		if i := indexWord(pos, "query"); i >= 0 && i+1 < len(pos) {
			a.sqlFacts(strings.ToLower(pos[i+1].s))
		}
		return
	}
	switch {
	case strings.Contains(joined, " auth print-access-token "), strings.Contains(joined, " auth print-identity-token "),
		strings.Contains(joined, " auth application-default print-access-token "), strings.Contains(joined, " auth print-refresh-token "):
		a.cred("token_print")
	case strings.Contains(joined, " auth list "), strings.Contains(joined, " config list "), strings.Contains(joined, " config get-value "),
		strings.Contains(joined, " config get "), strings.Contains(joined, " info "):
		a.recon("cloud_identity")
	case strings.Contains(joined, " secrets versions access "):
		a.cred("password_store")
	case strings.Contains(joined, " storage cp "), strings.Contains(joined, " storage mv "), strings.Contains(joined, " storage rsync "):
		i := indexWord(pos, "storage")
		args := pos[i+2:]
		if len(args) >= 2 {
			src, dst := args[0].s, args[len(args)-1].s
			if !strings.HasPrefix(src, "gs://") {
				a.read(src)
				if strings.HasPrefix(dst, "gs://") {
					a.exfil("cloud_bucket_upload")
				}
			}
		}
	}
	for _, w := range words {
		if w == "delete" || w == "destroy" {
			a.destructive("cloud_delete")
			break
		}
	}
	if strings.Contains(joined, " storage rm ") && (c.hasShort('r') || c.has("--recursive")) {
		a.destructive("cloud_delete")
	}
	// gcloud compute ssh VM --command "..." runs a remote shell line.
	for i, r := range rest {
		if r.s == "--command" && i+1 < len(rest) {
			a.sub(rest[i+1].s, Posix, OriginWrapper, c.depth+1, noFlow())
		} else if v, ok := strings.CutPrefix(r.s, "--command="); ok {
			a.sub(v, Posix, OriginWrapper, c.depth+1, noFlow())
		}
	}
}

func indexWord(pos []arg, w string) int {
	for i := range pos {
		if pos[i].s == w {
			return i
		}
	}
	return -1
}

func hAz(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	pos := positionalsOf(rest)
	joined := " " + strings.ToLower(strings.Join(strs(pos), " ")) + " "
	if c.name == "azcopy" {
		if len(pos) >= 3 && (pos[0].s == "copy" || pos[0].s == "cp" || pos[0].s == "sync") {
			src, dst := pos[1].s, pos[2].s
			if !strings.Contains(src, "://") {
				a.read(src)
				if strings.Contains(dst, "://") {
					a.exfil("cloud_bucket_upload")
				}
			}
		}
		if len(pos) >= 1 && (pos[0].s == "remove" || pos[0].s == "rm") {
			a.destructive("cloud_delete")
		}
		return
	}
	switch {
	case strings.Contains(joined, " account get-access-token "):
		a.cred("token_print")
	case strings.Contains(joined, " account show "), strings.Contains(joined, " account list "), strings.Contains(joined, " ad signed-in-user show "):
		a.recon("cloud_identity")
	case strings.Contains(joined, " keyvault secret show "), strings.Contains(joined, " keyvault secret download "), strings.Contains(joined, " keyvault key download "):
		a.cred("password_store")
	case strings.Contains(joined, " storage blob upload "), strings.Contains(joined, " storage blob upload-batch "),
		strings.Contains(joined, " storage file upload "), strings.Contains(joined, " storage fs file upload "):
		a.exfil("cloud_bucket_upload")
		for i, r := range rest {
			if (r.s == "--file" || r.s == "-f" || r.s == "--source" || r.s == "-s") && i+1 < len(rest) {
				a.read(rest[i+1].s)
			}
		}
	case strings.Contains(joined, " storage account keys list "), strings.Contains(joined, " acr credential show "), strings.Contains(joined, " acr login "):
		if !strings.Contains(joined, " acr login ") || containsArgFold(rest, "--expose-token") {
			a.cred("token_print")
		}
	}
	for _, p := range pos {
		if p.s == "delete" || p.s == "delete-batch" || p.s == "purge" {
			a.destructive("cloud_delete")
			break
		}
	}
}

func hCloudMisc(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	pos := positionalsOf(rest)
	words := strs(pos)
	joined := " " + strings.ToLower(strings.Join(words, " ")) + " "
	has := func(w string) bool { return strings.Contains(joined, " "+w+" ") }
	switch c.name {
	case "helm":
		if has("uninstall") || has("delete") {
			a.destructive("kubectl_delete")
		}
	case "rclone":
		if len(pos) >= 3 && (pos[0].s == "copy" || pos[0].s == "sync" || pos[0].s == "move" || pos[0].s == "copyto" || pos[0].s == "moveto") {
			src, dst := pos[1].s, pos[2].s
			_, srcRemote := remoteSpec(src)
			_, dstRemote := remoteSpec(dst)
			if !srcRemote {
				a.read(src)
				if dstRemote {
					a.exfil("cloud_bucket_upload")
				}
			}
		}
		if len(pos) >= 1 && (pos[0].s == "purge" || pos[0].s == "delete") {
			a.destructive("cloud_delete")
		}
	case "s3cmd", "s5cmd", "b2", "mc":
		if len(pos) >= 3 {
			switch pos[0].s {
			case "put", "sync", "cp", "mirror", "upload-file", "upload_file", "mv":
				src, dst := pos[1].s, pos[len(pos)-1].s
				local := !strings.Contains(src, "://") && (c.name != "mc" || strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~"))
				if c.name == "b2" && len(pos) >= 4 {
					src, local = pos[2].s, true
				}
				if local {
					a.read(src)
					if c.name != "mc" || !strings.HasPrefix(dst, "/") && !strings.HasPrefix(dst, ".") && !strings.HasPrefix(dst, "~") {
						a.exfil("cloud_bucket_upload")
					}
				}
			}
		}
		if len(pos) >= 1 && (pos[0].s == "rb" || pos[0].s == "del" || pos[0].s == "rm" && (c.hasShort('r') || c.has("--recursive", "--force"))) {
			a.destructive("cloud_delete")
		}
	case "heroku":
		for _, w := range words {
			if strings.HasSuffix(w, ":destroy") || w == "destroy" {
				a.destructive("cloud_delete")
			}
			if w == "auth:token" {
				a.cred("token_print")
			}
		}
	case "fly", "flyctl":
		if has("destroy") || has("delete") {
			a.destructive("cloud_delete")
		}
		if has("auth token") {
			a.cred("token_print")
		}
	case "vercel", "netlify", "railway", "supabase", "wrangler", "doctl", "oci":
		if has("delete") || has("remove") || has("rm") || has("destroy") || has("down") && c.name == "railway" {
			a.destructive("cloud_delete")
		}
		for _, w := range words {
			if strings.HasSuffix(w, ":delete") {
				a.destructive("cloud_delete")
			}
		}
		if c.name == "supabase" && has("db reset") {
			a.destructive("db_drop")
		}
		if c.name == "oci" && has("os object put") {
			a.exfil("cloud_bucket_upload")
		}
		if c.name == "doctl" && has("account get") {
			a.recon("cloud_identity")
		}
	}
}

var dbSpec = &optSpec{
	short: "cefhUdpPuDSEWvobi",
	long: longSet{"--command", "--execute", "--file", "--host", "--port", "--username", "--user", "--dbname", "--database",
		"--password", "--eval", "--query", "--set", "--variable", "--output", "--input-file"},
}

// hDB handles database clients: SQL given with -c/-e/--eval, as a
// positional, or on stdin.
func hDB(a *analyzer, c *simple, in flow, out *flow) {
	switch c.name {
	case "dropdb":
		a.destructive("db_drop")
		return
	case "mysqladmin":
		if containsArgFold(c.rest(), "drop") {
			a.destructive("db_drop")
		}
		if containsArgFold(c.rest(), "flush") {
			return
		}
		return
	case "pg_dump", "pg_dumpall", "mysqldump", "mongodump":
		return
	}
	o := parseOpts(c.rest(), dbSpec)
	var texts []string
	for _, v := range o.all("-c", "--command", "-e", "--execute", "--eval", "-Q", "-q", "--query") {
		texts = append(texts, v.s)
	}
	for _, f := range o.all("-f", "--file", "-i", "--input-file") {
		a.read(f.s)
	}
	switch c.name {
	case "sqlite3", "duckdb":
		if len(o.pos) > 0 {
			a.read(o.pos[0].s)
		}
		for _, p := range o.pos[min(1, len(o.pos)):] {
			texts = append(texts, p.s)
		}
	case "redis-cli":
		texts = append(texts, joinArgs(o.pos))
	case "mongosh", "mongo":
		// positional may be a connection string or a script
	}
	if static, _, has := c.input(a, in); has && static != nil {
		texts = append(texts, *static)
	}
	for _, t := range texts {
		if strings.TrimSpace(t) == "" {
			continue
		}
		a.inline("sql", t)
		a.sqlFacts(strings.ToLower(t))
	}
	for _, v := range o.all("-h", "--host") {
		a.host(v.s)
	}
	for _, p := range o.pos {
		if strings.Contains(p.s, "://") {
			a.url(p.s)
		}
	}
}

func hAppFramework(a *analyzer, c *simple, in flow, out *flow) {
	all := " " + strings.ToLower(joinArgs(c.rest())) + " "
	switch {
	case strings.Contains(all, " db:drop"), strings.Contains(all, " db:reset"), strings.Contains(all, " db:schema:load"),
		strings.Contains(all, " migrate reset "), strings.Contains(all, " migrate:fresh"), strings.Contains(all, " migrate:reset"),
		strings.Contains(all, " db:wipe"), strings.Contains(all, "--force-reset"), strings.Contains(all, " downgrade base "),
		strings.Contains(all, " db:migrate:undo:all"), strings.Contains(all, " reset_db "), strings.Contains(all, " clean ") && c.name == "flyway":
		a.destructive("db_drop")
	case strings.Contains(all, " flush ") && (c.name == "manage.py" || c.name == "django-admin"):
		a.destructive("db_truncate")
	}
}

func hPasswordStore(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	sub, r1 := subcommand(rest, nil)
	sub2, _ := subcommand(r1, nil)
	switch c.name {
	case "pass", "gopass":
		if sub == "show" || sub == "cat" || sub == "otp" || sub == "export" || sub != "" && sub != "ls" && sub != "list" && sub != "insert" &&
			sub != "generate" && sub != "init" && sub != "git" && sub != "version" && sub != "help" && sub != "rm" && sub != "mv" && sub != "cp" &&
			sub != "edit" && sub != "find" && sub != "grep" && sub != "search" && sub != "sync" {
			a.cred("password_store")
		}
	case "op":
		if sub == "read" || sub == "inject" || sub == "item" && sub2 == "get" || sub == "document" && sub2 == "get" || sub == "signin" && containsArgFold(rest, "--raw") {
			a.cred("password_store")
		}
	case "bw":
		if sub == "get" || sub == "export" || sub == "list" && sub2 == "items" || sub == "unlock" && containsArgFold(rest, "--raw") {
			a.cred("password_store")
		}
	case "lpass":
		if sub == "show" || sub == "export" {
			a.cred("password_store")
		}
	case "keepassxc-cli":
		if sub == "show" || sub == "export" || sub == "clip" || sub == "attachment-export" {
			a.cred("password_store")
		}
	case "vault":
		if sub == "read" || sub == "kv" && (sub2 == "get" || sub2 == "export") || sub == "print" && sub2 == "token" || sub == "token" && sub2 == "lookup" {
			if sub == "token" {
				a.recon("cloud_identity")
			} else {
				a.cred("password_store")
			}
		}
	case "sops":
		if sub == "decrypt" || c.hasShort('d', "--decrypt") || sub == "exec-env" || sub == "exec-file" {
			a.cred("password_store")
		}
	case "ansible-vault":
		if sub == "view" || sub == "decrypt" {
			a.cred("password_store")
		}
	case "chamber":
		if sub == "read" || sub == "export" || sub == "env" || sub == "list" {
			a.cred("password_store")
		}
	case "doppler", "infisical":
		if sub == "secrets" || sub == "export" {
			a.cred("password_store")
		}
	}
}

func hTokenTools(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	sub, _ := subcommand(rest, nil)
	switch {
	case strings.HasPrefix(c.name, "docker-credential-"), strings.HasPrefix(c.name, "git-credential-"):
		if sub == "get" || sub == "list" || sub == "fill" {
			a.cred("token_print")
		}
	case c.name == "firebase":
		if sub == "login:ci" {
			a.cred("token_print")
		}
	}
}

func hSecretScanners(a *analyzer, c *simple, in flow, out *flow) {
	a.recon("find_secrets")
	switch c.name {
	case "lazagne", "mimikatz", "secretsdump", "pypykatz":
		a.cred("keychain_dump")
	}
}
