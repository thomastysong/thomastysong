package classify

// Host tables. Each entry matches the named host and every subdomain of it.
// They are data, not logic: adding a host is a one-line change.
//
// Sources: the EXFIL_HOSTS list in the project's threat research
// (research/threats.md), the model-provider suffixes of uber/ADR
// (Discovery/adr_discovery/enumerator/markers.py, Apache-2.0), vendor
// documentation for the provider endpoints, and the public registries
// themselves. Hosts that could not be confirmed against a primary source in
// this build are still listed when being wrong only costs a label.
// UNVERIFIED: long-tail entries (regional LLM providers, lesser-known paste
// and tunnel services) come from general knowledge, not a fetched source.

var llmAPIHosts = []string{
	// Anthropic (research/agent-surfaces-a.md, Claude Code process identity).
	"api.anthropic.com", "claude.ai", "platform.claude.com", "mcp-proxy.anthropic.com",
	"anthropic.com",
	// OpenAI and ChatGPT-backed Codex.
	"api.openai.com", "chatgpt.com", "openai.azure.com", "services.ai.azure.com",
	"cognitiveservices.azure.com", "inference.ai.azure.com", "models.ai.azure.com",
	// Google.
	"generativelanguage.googleapis.com", "aiplatform.googleapis.com",
	"cloudcode-pa.googleapis.com",
	// GitHub Copilot.
	"api.githubcopilot.com", "githubcopilot.com", "models.github.ai",

	// Other first-party model APIs.
	"api.mistral.ai", "api.cohere.com", "api.cohere.ai", "api.groq.com",
	"api.x.ai", "api.deepseek.com", "api.together.xyz", "api.together.ai",
	"api.fireworks.ai", "api.perplexity.ai", "api.replicate.com",
	"api-inference.huggingface.co", "router.huggingface.co", "api.cerebras.ai",
	"api.sambanova.ai", "api.ai21.com", "api.voyageai.com", "api.moonshot.ai",
	"api.moonshot.cn", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
	"inference-api.nousresearch.com", "portal.nousresearch.com", "api.z.ai",
	"open.bigmodel.cn", "api.siliconflow.cn", "api.novita.ai",
	"api.hyperbolic.xyz", "api.minimax.chat", "api.deepinfra.com",
	"api.studio.nebius.com",
	// Agent vendors' own backends.
	"api.cursor.sh", "api2.cursor.sh", "api3.cursor.sh", "cursor.sh",
	"server.codeium.com", "api.codeium.com", "api.cline.bot", "ampcode.com",
	"api.augmentcode.com", "augmentcode.com",
	// Routers and gateways: a base-URL override to one of these sends the
	// whole conversation through a third party.
	"openrouter.ai", "api.requesty.ai", "router.requesty.ai", "api.portkey.ai",
	"gateway.ai.cloudflare.com", "ai-gateway.vercel.sh", "oai.helicone.ai",
	"api.helicone.ai",
}

var pasteHosts = []string{
	"pastebin.com", "paste.ee", "hastebin.com", "dpaste.com", "dpaste.org",
	"ghostbin.co", "rentry.co", "rentry.org", "pastes.io", "privatebin.net",
	"paste.rs", "ix.io", "sprunge.us", "termbin.com", "0x0.st",
	"paste.mozilla.org", "paste.debian.net", "paste.ubuntu.com", "pastie.org",
	"controlc.com", "justpaste.it", "paste.gg", "bpa.st", "paste.centos.org",
	"gist.github.com", "gist.githubusercontent.com", "pastebin.pl", "paste.sh",
	"clbin.com", "p.ip.fi", "write.as", "telegra.ph", "codepad.org", "del.dog",
	"katb.in", "paste.c-net.org", "pastebin.ubuntu.com", "paste.opensuse.org",
	"paste2.org", "snippet.host", "pst.klgrth.io",
	"notepad.pw", "textbin.net",
}

var fileShareHosts = []string{
	"transfer.sh", "file.io", "0x0.st", "gofile.io", "anonfiles.com",
	"bashupload.com", "bashupload.app", "catbox.moe", "uguu.se", "temp.sh",
	"tmpfiles.org", "filebin.net", "oshi.at", "wetransfer.com", "we.tl",
	"mega.nz", "mega.co.nz", "mediafire.com", "dropbox.com",
	"dropboxusercontent.com", "dropboxapi.com", "drive.google.com",
	"drive.usercontent.google.com", "box.com", "onedrive.live.com", "1drv.ms",
	"sharepoint.com", "pixeldrain.com", "krakenfiles.com", "sendspace.com",
	"ufile.io", "keep.sh", "x0.at", "envs.sh", "ttm.sh", "fileditch.com",
	"qu.ax", "send.vis.ee", "swisstransfer.com", "filetransfer.io",
	"easyupload.io", "upload.ee", "workupload.com", "files.fm", "icedrive.net",
	"pcloud.com", "limewire.com", "buzzheavier.com", "1fichier.com",
}

var tunnelHosts = []string{
	"ngrok.io", "ngrok-free.app", "ngrok-free.dev", "ngrok.app", "ngrok.dev",
	"ngrok.com", "trycloudflare.com", "cfargotunnel.com",
	"loca.lt", "localtunnel.me", "serveo.net", "localhost.run", "lhr.life",
	"pagekite.me", "tunnelto.dev", "telebit.cloud", "bore.pub",
	"playit.gg", "ply.gg", "ts.net", "devtunnels.ms", "zrok.io", "pinggy.io",
	"pinggy.link", "pinggy.online", "loclx.io", "localxpose.io",
	"tunnelmole.net", "portmap.io", "pktriot.net", "sharedwithexpose.com",
	"srv.us", "tuns.sh", "tunnel.pyjam.as",
	"app.github.dev", "githubpreview.dev",
}

var webhookSinkHosts = []string{
	"webhook.site", "requestbin.com", "requestbin.net", "pipedream.net",
	"pipedream.com", "interact.sh", "interactsh.com", "burpcollaborator.net",
	"oastify.com", "canarytokens.com", "canarytokens.org", "requestcatcher.com",
	"beeceptor.com", "mockbin.org", "hookbin.com", "postb.in", "ptsv2.com",
	"ptsv3.com", "webhook.cool", "requestinspector.com", "smee.io",
	"hookdeck.com", "hkdk.events", "typedwebhook.tools", "dnslog.cn",
	"ceye.io", "bxss.me", "xss.ht", "webhook-test.com", "usewebhook.com",
	"webhookrelay.com", "hooks.zapier.com", "maker.ifttt.com", "hook.make.com",
	"hook.integromat.com", "hook.eu1.make.com", "hook.eu2.make.com",
	"hook.us1.make.com", "hook.us2.make.com", "n8n.cloud",
	"requestrepo.com",
	"webhookinbox.com", "putsreq.com", "httpdump.app",

	"formspree.io", "formsubmit.co", "api.web3forms.com", "getform.io", "api.emailjs.com", "play.svix.com",
}

var chatWebhookHosts = []string{
	"discord.com", "discordapp.com", "hooks.slack.com",
	"slack.com", "api.telegram.org", "webhook.office.com",
	"chat.googleapis.com", "open.feishu.cn", "open.larksuite.com",
	"oapi.dingtalk.com", "qyapi.weixin.qq.com", "api.pushover.net", "ntfy.sh",
	"api.line.me", "notify-api.line.me", "api.pushbullet.com",
	"matrix.org",
	"api.twilio.com",
}

// Only shorteners where anyone can mint a link. Vendor-controlled redirectors
// (aka.ms, git.io) are not listed: an attacker cannot point them at a payload,
// and official installers use them.
var shortenerHosts = []string{
	"bit.ly", "tinyurl.com", "t.co", "is.gd", "v.gd", "ow.ly", "buff.ly",
	"rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly",
	"lnkd.in", "bl.ink", "short.io", "tny.im", "x.co", "shorte.st", "adf.ly",
	"bit.do", "soo.gd", "clck.ru", "u.to", "urlz.fr", "goo.su", "da.gd",
	"qrco.de", "tiny.one", "shrtco.de", "kutt.it", "dub.sh", "dub.co",
	"surl.li", "urlr.me", "t2m.io", "zpr.io",
	"shorturl.com", "tr.im", "j.mp",
}

var codeHosts = []string{
	"github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
	"codeberg.org", "sr.ht", "gitea.com", "gitee.com", "dev.azure.com",
	"visualstudio.com", "sourceforge.net", "huggingface.co", "hf.co",
	"launchpad.net",
	"source.developers.google.com", "gitflic.ru", "notabug.org",
	"git.kernel.org", "gist.github.com", "gist.githubusercontent.com",
	"gitlab.gnome.org", "salsa.debian.org", "framagit.org", "repo.or.cz",
}

var registryHosts = []string{
	// JavaScript.
	"registry.npmjs.org", "npmjs.com", "npmjs.org", "registry.yarnpkg.com",
	"yarnpkg.com", "jsr.io", "deno.land", "cdn.jsdelivr.net", "unpkg.com",
	"esm.sh", "registry.npmmirror.com", "pkg.github.com", "skypack.dev",
	"esm.run", "bun.sh",
	// Python.
	"pypi.org", "pythonhosted.org", "test.pypi.org", "conda.anaconda.org",
	"repo.anaconda.com", "anaconda.org", "pypi.tuna.tsinghua.edu.cn",
	// Rust, Go, Ruby, JVM, PHP, .NET, others.
	"crates.io", "proxy.golang.org", "sum.golang.org", "pkg.go.dev",
	"rubygems.org", "repo.maven.apache.org", "repo1.maven.org",
	"central.sonatype.com", "oss.sonatype.org", "plugins.gradle.org",
	"packagist.org", "nuget.org", "cocoapods.org", "pub.dev", "hex.pm",
	"cpan.org", "metacpan.org", "cran.r-project.org", "hackage.haskell.org",
	"jitpack.io", "clojars.org", "luarocks.org", "opam.ocaml.org",
	// Containers.
	"hub.docker.com", "docker.io", "docker.com", "ghcr.io", "quay.io",
	"gcr.io", "pkg.dev", "mcr.microsoft.com", "public.ecr.aws",
	"registry.k8s.io", "k8s.gcr.io", "registry.gitlab.com", "lscr.io",
	"registry.access.redhat.com", "nvcr.io",
	// OS packages and installers.
	"formulae.brew.sh", "deb.debian.org", "archive.ubuntu.com",
	"security.ubuntu.com", "dl-cdn.alpinelinux.org", "packages.microsoft.com",
	"chocolatey.org", "cdn.winget.microsoft.com", "winget.azureedge.net",
	"dl.fedoraproject.org", "mirrors.kernel.org", "ppa.launchpadcontent.net",
	"apt.llvm.org", "download.opensuse.org", "archlinux.org", "aur.archlinux.org",
	"nixos.org", "cache.nixos.org", "flathub.org", "snapcraft.io",
	"marketplace.visualstudio.com", "open-vsx.org",
	// Models, skills and MCP servers are packages too.
	"registry.ollama.ai", "ollama.com", "skills.sh",
	"registry.modelcontextprotocol.io", "smithery.ai",
}

// Hosts that ARE a metadata service by name. Addresses are in metadataIPs.
var metadataHosts = []string{
	"metadata.google.internal", "metadata.goog", "metadata",
	"instance-data", "instance-data.ec2.internal", "metadata.tencentyun.com",
	"metadata.platformequinix.com", "metadata.packet.net",
}

var dynDNSHosts = []string{
	"duckdns.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
	"servebeer.com", "serveftp.com", "servehttp.com", "myftp.org",
	"myvnc.com", "redirectme.net", "bounceme.net", "myddns.me", "no-ip.org",
	"no-ip.biz", "no-ip.info", "noip.com", "no-ip.com", "3utilities.com",
	"onthewifi.com", "gotdns.ch", "serveminecraft.net", "servegame.com",
	"webhop.me", "dyndns.org", "dynu.net", "dynu.com", "ddnsfree.com",
	"freeddns.org", "mywire.org", "accesscam.org", "camdvr.org", "casacam.net",
	"ddnsgeek.com", "giize.com", "gleeze.com", "kozow.com", "loseyourip.com",
	"ooguy.com", "theworkpc.com", "webredirect.org", "afraid.org", "mooo.com",
	"chickenkiller.com", "crabdance.com", "strangled.net",
	"twilightparadox.com", "us.to", "ignorelist.com", "jumpingcrab.com",
	"dnsdynamic.org", "changeip.com", "ydns.eu", "dedyn.io", "nsupdate.info",
	"tplinkdns.com", "synology.me", "myqnapcloud.com", "asuscomm.com",
	"myfritz.net", "nip.io", "sslip.io", "xip.io", "traefik.me",
	"localtest.me", "lvh.me", "dns.army", "dynv6.net", "dnsalias.com",
	"homeip.net", "selfip.com", "freemyip.com", "ddns.me", "dyn.dns.he.net",
	"myds.me", "dns-dynamic.net", "ddnsking.com", "publicvm.com", "linkpc.net",
	"rbndr.us", "1u.ms",
}

var onionGateways = []string{
	"onion.to", "onion.ws", "onion.ly", "onion.pet", "tor2web.org",
	"onion.link", "onion.cab", "tor2web.io", "onion.sh", "onion.casa",
}

var objectStorageHosts = []string{
	"storage.googleapis.com", "storage.cloud.google.com",
	"firebasestorage.googleapis.com", "firebasestorage.app",
	"blob.core.windows.net", "dfs.core.windows.net", "file.core.windows.net",
	"r2.cloudflarestorage.com", "r2.dev", "digitaloceanspaces.com",
	"backblazeb2.com", "wasabisys.com", "linodeobjects.com",
	"myqcloud.com", "storage.yandexcloud.net", "objectstorage.oraclecloud.com",
	"cloud-object-storage.appdomain.cloud", "storjshare.io", "scw.cloud",
	"contabostorage.com", "idrivee2.com", "tigris.dev", "vultrobjects.com",
	"upcloudobjects.com", "storage.bunnycdn.com",
}

var mailHosts = []string{
	"smtp.gmail.com", "smtp-relay.gmail.com", "aspmx.l.google.com",
	"gmail.googleapis.com", "smtp.office365.com", "smtp-mail.outlook.com",
	"mail.protection.outlook.com", "smtp.mail.yahoo.com", "sendgrid.net",
	"api.sendgrid.com", "mailgun.org", "api.mailgun.net", "api.eu.mailgun.net",
	"postmarkapp.com", "api.resend.com", "smtp.resend.com", "api.mailjet.com",
	"in-v3.mailjet.com", "api.sparkpost.com", "sparkpostmail.com",
	"api.brevo.com", "smtp-relay.brevo.com", "smtp-relay.sendinblue.com",
	"api.sendinblue.com", "mandrillapp.com", "api.mailchimp.com",
	"smtp.zoho.com", "smtp.fastmail.com", "smtp.protonmail.ch",
	"api.elasticemail.com", "smtp.elasticemail.com", "mailtrap.io",
	"api.smtp2go.com", "mail.smtp2go.com", "api.mailersend.com",
	"smtp.mailersend.net", "api.loops.so", "api.postmarkapp.com",
	"smtp.mail.me.com", "smtp.aol.com", "smtp.yandex.com", "smtp.mail.ru",
	"smtp.qq.com", "smtp.163.com",
}

var freeHostingHosts = []string{
	"onrender.com", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
	"herokuapp.com", "fly.dev", "railway.app", "replit.dev",
	"repl.co", "replit.app", "glitch.me", "deno.dev", "web.app",
	"firebaseapp.com", "github.io", "gitlab.io", "azurewebsites.net",
	"azurestaticapps.net", "cloudfunctions.net", "run.app", "appspot.com",
	"on.aws", "surge.sh", "now.sh", "pythonanywhere.com",
	"000webhostapp.com", "infinityfreeapp.com", "koyeb.app", "northflank.app",
	"cyclic.app", "adaptable.app", "deta.dev", "deta.app", "val.run",
	"supabase.co", "convex.site", "convex.cloud", "bubbleapps.io",
	"webflow.io", "wixsite.com", "weebly.com", "blogspot.com", "wordpress.com",
	"csb.app", "stackblitz.io", "webcontainer.io",
	"hf.space", "streamlit.app", "gradio.live", "modal.run", "zeabur.app",
	"sevalla.app", "kinsta.app", "ondigitalocean.app",

	"edgeone.app", "lovable.app", "bolt.host", "v0.app",
	"gitpod.io",
}

// loopbackHosts are names that reach the local machine.
var loopbackHosts = []string{
	"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
	"host.docker.internal", "gateway.docker.internal",
	"host.containers.internal", "kubernetes.docker.internal", "localtest.me",
	"lvh.me", "lacolhost.com", "vcap.me",
}

// wildcardDNS are services that resolve <ip>.<suffix> to <ip>. A URL such as
// http://169.254.169.254.nip.io/ therefore reaches the metadata service
// while looking like a public hostname.
var wildcardDNS = []string{"nip.io", "sslip.io", "xip.io", "traefik.me", "localtest.me", "lvh.me"}

// mailLabels are leftmost labels that conventionally name a mail server.
var mailLabels = lazySet{list: []string{
	"smtp", "mail", "mx", "imap", "pop",
	"pop3", "smtps", "mailout", "smtp-relay",
	"email", "webmail", "mailgw", "mx1", "mx2",
	"smtp1", "smtp2", "mail1", "mail2", "mta",
}}
