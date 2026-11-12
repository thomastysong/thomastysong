package privacy

import (
	"fmt"
	"testing"

	"github.com/thomastysong/spoor/internal/classify"
)

func TestScratchPaths(t *testing.T) {
	for _, p := range []string{"~/.netrc", "~/.pgpass", "db.conf", ".env", "~/.aws/credentials", "~/.docker/config.json", "~/.npmrc", "~/.pypirc", "~/.git-credentials", "/etc/shadow", "~/.kube/config", "id_rsa", "~/.ssh/id_ed25519", "server.key", "~/.my.cnf", "token.txt", "~/.config/gh/hosts.yml", "secrets.yaml", "/tmp/x", "~/.bashrc", ".env.local", "~/.vault-token", "credentials.json"} {
		fmt.Printf("%s -> %v\n", p, classify.PathClasses(p, classify.PathCtx{CWD: "/home/bob/w", Home: "/home/bob"}))
	}
	for _, c := range [][]string{{"mount", "-o", "username=bob,password=Sommer2026x", "//h/s", "/mnt"}, {"ldapsearch", "-x", "-D", "cn=admin", "-w", "Sommer2026x"}, {"zip", "-P", "Sommer2026x", "a.zip", "f"}, {"unzip", "-P", "Sommer2026x", "a.zip"}, {"sqlplus", "scott/Sommer2026x@orcl"}, {"psexec", "\\\\h", "-u", "bob", "-p", "Sommer2026x", "cmd"}, {"az", "login", "-u", "bob", "-p", "Sommer2026x"}, {"mongosh", "-u", "bob", "-p", "Sommer2026x"}, {"wget", "--password=Sommer2026x", "u"}, {"vault", "login", "Sommer2026x"}, {"openssl", "enc", "-pass", "pass:Sommer2026x"}, {"rar", "a", "-pSommer2026x", "x.rar"}, {"mysqldump", "-pSommer2026x"}, {"sshpass", "-p", "Sommer2026x", "ssh", "h"}} {
		fmt.Printf("%q -> %q\n", c, classify.RedactArgs(c))
	}
}
