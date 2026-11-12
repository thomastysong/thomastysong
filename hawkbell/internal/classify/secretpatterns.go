package classify

import (
	"regexp"
	"strings"
	"sync"
)

// Secret kinds reported in SecretHit.Kind. The vocabulary is closed: rules and
// dashboards can enumerate it with SecretKinds.
const (
	KindAWSAccessKeyID        = "aws_access_key_id"
	KindAWSSecret             = "aws_secret"
	KindGitHubPAT             = "github_pat"
	KindGitHubOAuth           = "github_oauth"
	KindGitHubAppUser         = "github_app_user"
	KindGitHubAppServer       = "github_app_server"
	KindGitHubRefresh         = "github_refresh"
	KindGitHubFineGrainedPAT  = "github_fine_grained_pat"
	KindGitLabPAT             = "gitlab_pat"
	KindAnthropicAPIKey       = "anthropic_api_key"
	KindOpenAIAPIKey          = "openai_api_key"
	KindOpenRouterAPIKey      = "openrouter_api_key"
	KindLLMAPIKey             = "llm_api_key"
	KindGoogleAPIKey          = "google_api_key"
	KindGoogleOAuthSecret     = "google_oauth_client_secret"
	KindGoogleOAuthToken      = "google_oauth_token"
	KindGCPServiceAccount     = "gcp_service_account"
	KindAzureStorageKey       = "azure_storage_key"
	KindAzureSAS              = "azure_sas"
	KindAzureClientSecret     = "azure_client_secret"
	KindSlackToken            = "slack_token"
	KindSlackWebhook          = "slack_webhook"
	KindDiscordWebhook        = "discord_webhook"
	KindTelegramBotToken      = "telegram_bot_token"
	KindStripeKey             = "stripe_key"
	KindTwilio                = "twilio"
	KindSendGrid              = "sendgrid"
	KindNPMToken              = "npm_token"
	KindPyPIToken             = "pypi_token"
	KindHuggingFaceToken      = "huggingface_token"
	KindJWT                   = "jwt"
	KindPrivateKeyBlock       = "private_key_block"
	KindBasicAuthURL          = "basic_auth_url"
	KindDatabaseURL           = "database_url_with_password"
	KindBearerHeader          = "bearer_header"
	KindBasicAuthHeader       = "basic_auth_header"
	KindCookieHeader          = "cookie_header"
	KindPassword              = "password"
	KindGenericSecret         = "generic_secret"
	KindDigitalOceanToken     = "digitalocean_token"
	KindShopifyToken          = "shopify_token"
	KindDatabricksToken       = "databricks_token"
	KindVaultToken            = "vault_token"
	KindAgeSecretKey          = "age_secret_key"
	KindDockerPAT             = "docker_pat"
	KindTailscaleKey          = "tailscale_key"
	KindAtlassianToken        = "atlassian_token"
	KindNotionToken           = "notion_token"
	KindLinearAPIKey          = "linear_api_key"
	KindFigmaToken            = "figma_token"
	KindSentryToken           = "sentry_token"
	KindGrafanaToken          = "grafana_token"
	KindSupabaseToken         = "supabase_token"
	KindPostmanAPIKey         = "postman_api_key"
	KindNewRelicKey           = "newrelic_key"
	KindMailchimpAPIKey       = "mailchimp_api_key"
	KindArtifactoryToken      = "artifactory_token"
	KindPulumiToken           = "pulumi_token"
	KindHerokuAPIKey          = "heroku_api_key"
	KindDopplerToken          = "doppler_token"
	KindTerraformToken        = "terraform_token"
	KindPlanetScaleToken      = "planetscale_token"
	KindLangSmithKey          = "langsmith_key"
	KindOnePasswordToken      = "onepassword_token"
	KindRubyGemsKey           = "rubygems_key"
	KindFlyToken              = "fly_token"
	KindSquareToken           = "square_token"
	KindURLParam              = "url_param"     // RedactURL / RedactArgs: value of a secret-named query parameter
	KindSensitiveKey          = "sensitive_key" // RedactMap: value under a secret-named key
	kindRedactionFailureLabel = "error"         // marker kind when redaction itself failed
)

// SecretKinds returns every value SecretHit.Kind (and a redaction marker) can
// carry, in a stable order.
func SecretKinds() []string {
	return []string{
		KindAWSAccessKeyID, KindAWSSecret, KindGitHubPAT, KindGitHubOAuth,
		KindGitHubAppUser, KindGitHubAppServer, KindGitHubRefresh,
		KindGitHubFineGrainedPAT, KindGitLabPAT, KindAnthropicAPIKey,
		KindOpenAIAPIKey, KindOpenRouterAPIKey, KindLLMAPIKey, KindGoogleAPIKey,
		KindGoogleOAuthSecret, KindGoogleOAuthToken, KindGCPServiceAccount,
		KindAzureStorageKey, KindAzureSAS, KindAzureClientSecret, KindSlackToken,
		KindSlackWebhook, KindDiscordWebhook, KindTelegramBotToken, KindStripeKey,
		KindTwilio, KindSendGrid, KindNPMToken, KindPyPIToken,
		KindHuggingFaceToken, KindJWT, KindPrivateKeyBlock, KindBasicAuthURL,
		KindDatabaseURL, KindBearerHeader, KindBasicAuthHeader, KindCookieHeader,
		KindPassword, KindGenericSecret, KindDigitalOceanToken, KindShopifyToken,
		KindDatabricksToken, KindVaultToken, KindAgeSecretKey, KindDockerPAT,
		KindTailscaleKey, KindAtlassianToken, KindNotionToken, KindLinearAPIKey,
		KindFigmaToken, KindSentryToken, KindGrafanaToken, KindSupabaseToken,
		KindPostmanAPIKey, KindNewRelicKey, KindMailchimpAPIKey,
		KindArtifactoryToken, KindPulumiToken, KindHerokuAPIKey, KindDopplerToken,
		KindTerraformToken, KindPlanetScaleToken, KindLangSmithKey,
		KindOnePasswordToken, KindRubyGemsKey, KindFlyToken, KindSquareToken,
		KindURLParam, KindSensitiveKey,
	}
}

// detector is one provider-specific pattern. Token formats come from the
// providers' public documentation and the open secret-scanning rule sets
// (gitleaks, detect-secrets); they were not re-verified against live issuers
// in this build, so each pattern is deliberately a little wider than the
// documented format and is gated by entropy and a placeholder filter instead.
// UNVERIFIED: exact lengths of provider tokens.
type detector struct {
	kind string
	expr string
	// keywords gate the regex: it runs only when at least one occurs. With cs
	// they are matched case-sensitively against the text, otherwise against
	// its ASCII-lowered copy (so they must be lower case).
	keywords []string
	cs       bool
	group    int     // capture group reported as the secret
	body     int     // capture group that is entropy/placeholder gated (0: group)
	minEnt   float64 // 0 disables the entropy gate
	// prefixKinds overrides kind by the secret's prefix.
	prefixKinds []prefixKind

	once sync.Once
	re   *regexp.Regexp
}

type prefixKind struct{ prefix, kind string }

// regex compiles lazily: a hook invocation is a fresh process and most
// detectors never run in it, so compiling all of them at init would be wasted
// start-up time on the hot path.
func (d *detector) regex() *regexp.Regexp {
	d.once.Do(func() { d.re = regexp.MustCompile(d.expr) })
	return d.re
}

func (d *detector) wanted(s, low string) bool {
	if len(d.keywords) == 0 {
		return true
	}
	hay := low
	if d.cs {
		hay = s
	}
	for _, k := range d.keywords {
		if strings.Contains(hay, k) {
			return true
		}
	}
	return false
}

func (d *detector) kindFor(secret string) string {
	for _, pk := range d.prefixKinds {
		if strings.HasPrefix(secret, pk.prefix) {
			return pk.kind
		}
	}
	return d.kind
}

// detectors is ordered by priority: when two hits overlap the earlier
// detector's kind wins. Specific providers therefore precede generic shapes.
var detectors = []*detector{
	{kind: KindAnthropicAPIKey, expr: `\b(sk-ant-(?:[a-z]{2,8}[0-9]{2}-)?([A-Za-z0-9_\-]{24,}))`,
		keywords: []string{"sk-ant-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindOpenRouterAPIKey, expr: `\b(sk-or-(?:v1-)?([a-f0-9]{48,}))\b`,
		keywords: []string{"sk-or-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindOpenAIAPIKey, expr: `\b(sk-(?:proj|svcacct|admin|None)-([A-Za-z0-9_\-]{32,}))`,
		keywords: []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-None-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindOpenAIAPIKey, expr: `\b(sk-([A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}))\b`,
		keywords: []string{"T3BlbkFJ"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindAWSAccessKeyID, expr: `\b((?:AKIA|ASIA|ABIA|ACCA)([A-Z0-9]{16}))\b`,
		keywords: []string{"AKIA", "ASIA", "ABIA", "ACCA"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindAWSSecret, expr: `(?i)(?:aws[_\-.]?secret[_\-.]?access[_\-.]?key|aws[_\-.]?secret[_\-.]?key|secret[_\-.]?access[_\-.]?key|aws[_\-.]?sk)["']?\s{0,4}(?:=>|:=|=|:)\s{0,4}["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`,
		keywords: []string{"secret", "aws_sk", "aws-sk"}, group: 1, minEnt: 3.5},
	{kind: KindGitHubPAT, expr: `\b(gh[pousr]_([A-Za-z0-9]{36,}))\b`,
		keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, cs: true, group: 1, body: 2, minEnt: 3.0,
		prefixKinds: []prefixKind{{"ghp_", KindGitHubPAT}, {"gho_", KindGitHubOAuth}, {"ghu_", KindGitHubAppUser}, {"ghs_", KindGitHubAppServer}, {"ghr_", KindGitHubRefresh}}},
	{kind: KindGitHubFineGrainedPAT, expr: `\b(github_pat_([A-Za-z0-9_]{36,}))`,
		keywords: []string{"github_pat_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindGitLabPAT, expr: `\b(gl(?:pat|dt|rt|ptt|cbt|ft|soat|imt|oas|agent)-([A-Za-z0-9_\-.]{20,}))`,
		keywords: []string{"glpat-", "gldt-", "glrt-", "glptt-", "glcbt-", "glft-", "glsoat-", "glimt-", "gloas-", "glagent-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindGoogleAPIKey, expr: `\b(AIza([0-9A-Za-z_\-]{35}))(?:[^0-9A-Za-z_\-]|$)`,
		keywords: []string{"AIza"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindGoogleOAuthSecret, expr: `\b(GOCSPX-([A-Za-z0-9_\-]{28}))`,
		keywords: []string{"GOCSPX-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindGoogleOAuthToken, expr: `\b(ya29\.([A-Za-z0-9_\-]{30,}))`,
		keywords: []string{"ya29."}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindAzureStorageKey, expr: `(?i)(?:AccountKey|SharedAccessKey)\s{0,4}=\s{0,4}([A-Za-z0-9+/]{43,86}={1,2})`,
		keywords: []string{"accountkey", "sharedaccesskey"}, group: 1, minEnt: 3.5},
	{kind: KindAzureSAS, expr: `(?i)[?&;]sig=([A-Za-z0-9%+/]{40,}={0,2})`,
		keywords: []string{"sig="}, group: 1, minEnt: 3.5},
	{kind: KindAzureClientSecret, expr: `(?:^|[^A-Za-z0-9_~.\-])([A-Za-z0-9_~.\-]{3}8Q~([A-Za-z0-9_~.\-]{31,34}))(?:[^A-Za-z0-9_~.\-]|$)`,
		keywords: []string{"8Q~"}, cs: true, group: 1, body: 2, minEnt: 3.5},
	{kind: KindSlackToken, expr: `\b(xox[abeoprs]-([A-Za-z0-9\-]{10,}))`,
		keywords: []string{"xox"}, cs: true, group: 1, body: 2, minEnt: 2.5},
	{kind: KindSlackToken, expr: `\b(xapp-[0-9]-([A-Za-z0-9\-]{20,}))`,
		keywords: []string{"xapp-"}, cs: true, group: 1, body: 2, minEnt: 2.5},
	{kind: KindSlackWebhook, expr: `(?i)hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9+/_\-]{20,})`,
		keywords: []string{"hooks.slack.com/"}, group: 1, minEnt: 3.0},
	{kind: KindDiscordWebhook, expr: `(?i)discord(?:app)?\.com/api/(?:v[0-9]{1,2}/)?webhooks/([0-9]{5,25}/[A-Za-z0-9_\-]{30,})`,
		keywords: []string{"/api/webhooks/", "/webhooks/"}, group: 1, minEnt: 3.0},
	{kind: KindTelegramBotToken, expr: `(?:^|[^0-9A-Za-z])([0-9]{8,10}:(AA[A-Za-z0-9_\-]{33}))(?:[^A-Za-z0-9_\-]|$)`,
		keywords: []string{":AA"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindStripeKey, expr: `\b((?:sk|rk)_(?:live|test)_([A-Za-z0-9]{16,}))\b`,
		keywords: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindStripeKey, expr: `\b(whsec_([A-Za-z0-9]{24,}))\b`,
		keywords: []string{"whsec_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindTwilio, expr: `\b(SK([0-9a-fA-F]{32}))\b`,
		keywords: []string{"SK"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindTwilio, expr: `(?i)twilio[^\n]{0,40}?\b([0-9a-f]{32})\b`,
		keywords: []string{"twilio"}, group: 1, minEnt: 3.0},
	{kind: KindSendGrid, expr: `\b(SG\.([A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}))`,
		keywords: []string{"SG."}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindNPMToken, expr: `\b(npm_([A-Za-z0-9]{36}))\b`,
		keywords: []string{"npm_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindNPMToken, expr: `(?i):_(?:authToken|auth|password)\s{0,4}=\s{0,4}"?([^\s"]{8,})`,
		keywords: []string{":_auth", ":_password"}, group: 1, minEnt: 2.5},
	{kind: KindPyPIToken, expr: `\b(pypi-(Ag[A-Za-z0-9_\-]{50,}))`,
		keywords: []string{"pypi-Ag"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindHuggingFaceToken, expr: `\b(hf_([A-Za-z0-9]{30,}))\b`,
		keywords: []string{"hf_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindLLMAPIKey, expr: `\b((?:gsk_|xai-|r8_|pplx-)([A-Za-z0-9]{36,}))\b`,
		keywords: []string{"gsk_", "xai-", "r8_", "pplx-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindDigitalOceanToken, expr: `\b(do[opr]_v1_([a-f0-9]{64}))\b`,
		keywords: []string{"dop_v1_", "doo_v1_", "dor_v1_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindShopifyToken, expr: `\b(shp(?:at|ca|pa|ss)_([a-fA-F0-9]{32}))\b`,
		keywords: []string{"shpat_", "shpca_", "shppa_", "shpss_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindDatabricksToken, expr: `\b(dapi([a-f0-9]{32})(?:-[0-9])?)\b`,
		keywords: []string{"dapi"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindVaultToken, expr: `\b(hv[sb]\.([A-Za-z0-9_\-]{24,}))`,
		keywords: []string{"hvs.", "hvb."}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindAgeSecretKey, expr: `\b(AGE-SECRET-KEY-1([QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}))\b`,
		keywords: []string{"AGE-SECRET-KEY-1"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindDockerPAT, expr: `\b(dckr_pat_([A-Za-z0-9_\-]{27,}))`,
		keywords: []string{"dckr_pat_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindTailscaleKey, expr: `\b(tskey-(?:auth|api|client)-([A-Za-z0-9\-]{20,}))`,
		keywords: []string{"tskey-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindAtlassianToken, expr: `\b(ATATT3([A-Za-z0-9_\-=]{60,}))`,
		keywords: []string{"ATATT3"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindNotionToken, expr: `\b((?:secret_|ntn_)([A-Za-z0-9]{40,50}))\b`,
		keywords: []string{"secret_", "ntn_"}, cs: true, group: 1, body: 2, minEnt: 3.5},
	{kind: KindLinearAPIKey, expr: `\b(lin_api_([A-Za-z0-9]{40}))\b`,
		keywords: []string{"lin_api_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindFigmaToken, expr: `\b(figd_([A-Za-z0-9_\-]{40,}))`,
		keywords: []string{"figd_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindSentryToken, expr: `\b(sntry[su]_([A-Za-z0-9_+/=\-]{40,}))`,
		keywords: []string{"sntrys_", "sntryu_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindGrafanaToken, expr: `\b(gl(?:c|sa)_([A-Za-z0-9+/=_]{32,}))`,
		keywords: []string{"glc_", "glsa_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindSupabaseToken, expr: `\b(sbp_([a-f0-9]{40}))\b`,
		keywords: []string{"sbp_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindPostmanAPIKey, expr: `\b(PMAK-([0-9a-f]{24}-[0-9a-f]{34}))\b`,
		keywords: []string{"PMAK-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindNewRelicKey, expr: `\b(NR(?:AK|II|JS)-([A-Za-z0-9]{27,}))\b`,
		keywords: []string{"NRAK-", "NRII-", "NRJS-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindMailchimpAPIKey, expr: `\b(([0-9a-f]{32})-us[0-9]{1,2})\b`,
		keywords: []string{"-us"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindArtifactoryToken, expr: `\b(AKCp([A-Za-z0-9]{69}))\b`,
		keywords: []string{"AKCp"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindPulumiToken, expr: `\b(pul-([a-f0-9]{40}))\b`,
		keywords: []string{"pul-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindHerokuAPIKey, expr: `\b(HRKU-([A-Za-z0-9_\-]{58,}))`,
		keywords: []string{"HRKU-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindDopplerToken, expr: `\b(dp\.(?:pt|st|sa|ct|scim|audit)\.([A-Za-z0-9]{40,}))\b`,
		keywords: []string{"dp.pt.", "dp.st.", "dp.sa.", "dp.ct.", "dp.scim.", "dp.audit."}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindTerraformToken, expr: `\b([A-Za-z0-9]{14}\.atlasv1\.([A-Za-z0-9_\-=]{60,}))`,
		keywords: []string{".atlasv1."}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindPlanetScaleToken, expr: `\b(pscale_(?:tkn|pw|oauth)_([A-Za-z0-9_\-.]{32,}))`,
		keywords: []string{"pscale_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindLangSmithKey, expr: `\b(lsv2_(?:pt|sk)_([a-f0-9]{32}_[a-f0-9]{10}))\b`,
		keywords: []string{"lsv2_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindOnePasswordToken, expr: `\b(ops_(eyJ[A-Za-z0-9+/=_\-]{100,}))`,
		keywords: []string{"ops_eyJ"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindRubyGemsKey, expr: `\b(rubygems_([a-f0-9]{48}))\b`,
		keywords: []string{"rubygems_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindFlyToken, expr: `\b((?:fo1_|fm[12]_)([A-Za-z0-9+/=_\-]{43,}))`,
		keywords: []string{"fo1_", "fm1_", "fm2_"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindSquareToken, expr: `\b(sq0(?:atp|csp)-([A-Za-z0-9_\-]{22,}))`,
		keywords: []string{"sq0atp-", "sq0csp-"}, cs: true, group: 1, body: 2, minEnt: 3.0},
	{kind: KindJWT, expr: `\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.([A-Za-z0-9_\-]{10,}))`,
		keywords: []string{"eyJ"}, cs: true, group: 1, body: 2, minEnt: 2.5},
	// Generic "sk-" keys (OpenAI legacy and the many OpenAI-compatible
	// providers). Last among the prefixed kinds so a provider-specific match
	// on the same bytes keeps its name.
	{kind: KindLLMAPIKey, expr: `\b(sk-([A-Za-z0-9]{32,}))\b`,
		keywords: []string{"sk-"}, cs: true, group: 1, body: 2, minEnt: 3.5},
}

// Priorities for the hand-written detectors, relative to the table above
// (table index is the priority of a table detector).
const (
	prioPrivateKey = -1 // a key block always wins: it must be redacted whole
	prioURLCreds   = 1000
	prioAuthHeader = 1001
	prioCookie     = 1002
	prioAssignment = 1003
)

// dbSchemes are URL schemes whose userinfo is a database credential.
var dbSchemes = lazySet{list: []string{
	"postgres", "postgresql", "mysql", "mariadb",
	"mongodb", "mongodb+srv", "redis", "rediss",
	"amqp", "amqps", "mssql", "sqlserver",
	"oracle", "clickhouse", "cockroachdb", "snowflake",
	"cassandra", "couchbase", "neo4j", "bolt",
	"memcached", "nats", "kafka", "db2",
	"sqlite", "libsql", "influxdb", "trino",
	"presto", "vertica", "redshift", "mysql+pymysql",
	"postgresql+psycopg2", "postgresql+asyncpg", "mysqlx",
}}

var (
	urlCredsOnce sync.Once
	urlCredsRe   *regexp.Regexp

	authHeaderOnce sync.Once
	authHeaderRe   *regexp.Regexp
	bearerRe       *regexp.Regexp

	cookieOnce sync.Once
	cookieRe   *regexp.Regexp

	assignOnce sync.Once
	assignRe   *regexp.Regexp
	flagRe     *regexp.Regexp

	pkOnce    sync.Once
	pkBeginRe *regexp.Regexp
	pkEndRe   *regexp.Regexp
	gcpSARe   *regexp.Regexp
)

func urlCredsRegex() *regexp.Regexp {
	urlCredsOnce.Do(func() {
		// scheme://user[:password]@host. The password class excludes "/" so
		// the match cannot run past the authority; being greedy it ends at the
		// LAST "@" of the authority, which is where URL parsers split too.
		urlCredsRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]{1,30})://([^\s/:@'"<>\x60]*)(?::([^\s/'"<>\x60]*))?@[^\s/:@'"<>\x60]`)
	})
	return urlCredsRe
}

func authHeaderRegexes() (*regexp.Regexp, *regexp.Regexp) {
	authHeaderOnce.Do(func() {
		authHeaderRe = regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?\s{0,4}[:=]\s{0,4}["']?(?:(bearer|basic|token|digest|apikey|api-key|oauth|negotiate|ntlm|sso-key|bot|key)[ \t]+)?([^\s"',;]{6,})`)
		bearerRe = regexp.MustCompile(`(?i)\bbearer[ \t]+([A-Za-z0-9_\-.~+/]{20,}={0,2})`)
	})
	return authHeaderRe, bearerRe
}

func cookieRegex() *regexp.Regexp {
	cookieOnce.Do(func() {
		cookieRe = regexp.MustCompile(`(?i)\b(?:set-)?cookie["']?\s{0,4}:\s{0,4}["']?([A-Za-z0-9_.\-]{1,64}=[^\s;"']{8,}(?:;[ \t]*[A-Za-z0-9_.\-]{1,64}(?:=[^\s;"']*)?)*)`)
	})
	return cookieRe
}

// assignStems are the substrings a name must contain before the (more
// expensive) assignment regexes run and before secretName is consulted.
var assignStems = []string{"pass", "pwd", "secret", "token", "key", "credential", "auth", "bearer", "jwt", "cookie"}

func assignRegexes() (*regexp.Regexp, *regexp.Regexp) {
	assignOnce.Do(func() {
		const stems = `(?:pass|pwd|secret|token|key|credential|auth|bearer|jwt|cookie)`
		const value = `(?:"((?:[^"\\\n]|\\.)+)"|'([^'\n]+)'|([^\s"'\x60;&<>|]+))`
		// name <sep> value, where the name contains a stem. The name is
		// classified by secretName afterwards; the regex only finds candidates.
		assignRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*` + stems + `[A-Za-z0-9_.\-]*)["']?\s{0,4}(?:===?|=>|:=|=|:)\s{0,4}` + value)
		// --flag value (space separated).
		flagRe = regexp.MustCompile(`(?i)(?:^|[\s"'=(\[,])(-{1,2}[A-Za-z0-9_\-]*` + stems + `[A-Za-z0-9_\-]*)[ \t]+` + value)
	})
	return assignRe, flagRe
}

func privateKeyRegexes() (begin, end, gcp *regexp.Regexp) {
	pkOnce.Do(func() {
		pkBeginRe = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----`)
		pkEndRe = regexp.MustCompile(`-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----`)
		gcpSARe = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	})
	return pkBeginRe, pkEndRe, gcpSARe
}
