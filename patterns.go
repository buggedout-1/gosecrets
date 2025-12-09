package main

// DefaultPatterns contains all regex patterns for secret detection
// Ported from patterns.txt
var DefaultPatterns = map[string]string{
	// ============================================
	// Generic API Keys and Secrets
	// ============================================
	"Generic API Key":       `(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`,
	"Generic Secret Key":    `(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`,
	"Generic Access Token":  `(?i)(?:access[_-]?token|accesstoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`,
	"Generic Auth Token":    `(?i)(?:auth[_-]?token|authtoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`,
	"Generic Private Key":   `(?i)(?:private[_-]?key|privatekey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`,
	"Generic Client Secret": `(?i)(?:client[_-]?secret|clientsecret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{32,})['"]`,
	"Generic Password":      `(?i)(?:password|passwd|pwd|dbPassword)\s*[:=]\s*['"]([^'"/@]{8,64})['"]`,

	// ============================================
	// AWS
	// ============================================
	"AWS Access Key ID":     `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
	"AWS Secret Access Key": `(?i)(?:aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key|secret[_-]?access[_-]?key|aws_secret_access_key)['"\s]*[:=]['"\s]*['"]?([A-Za-z0-9/+=]{40})['"]?`,
	"AWS Session Token":     `(?i)(?:aws)?_?session_?token['"\s]*[:=]['"\s]*([A-Za-z0-9/+=]{100,})`,
	"AWS ARN":               `arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9-_/]+`,

	// ============================================
	// Google/GCP
	// ============================================
	"Google API Key":              `AIza[0-9A-Za-z\-_]{35}`,
	"Google OAuth Client ID":      `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"Google OAuth Client Secret":  `(?i)google[_-]?(?:client[_-]?)?secret['"\s]*[:=]['"\s]*([a-zA-Z0-9_-]{24})`,
	"Google Cloud Service Account": `(?i)"type"\s*:\s*"service_account"`,
	"Firebase URL":                `https://[a-z0-9-]+\.firebaseio\.com`,
	"Firebase API Key":            `(?i)(?:firebase|FIREBASE)[_-]?(?:API[_-]?KEY|apiKey)['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{39})`,

	// ============================================
	// GitHub
	// ============================================
	"GitHub Personal Access Token (Classic)": `ghp_[A-Za-z0-9]{36}`,
	"GitHub OAuth Access Token":              `gho_[A-Za-z0-9]{36}`,
	"GitHub User-to-Server Token":            `ghu_[A-Za-z0-9]{36}`,
	"GitHub Server-to-Server Token":          `ghs_[A-Za-z0-9]{36}`,
	"GitHub Refresh Token":                   `ghr_[A-Za-z0-9]{36}`,
	"GitHub Fine-Grained PAT":                `github_pat_[A-Za-z0-9_]{5,}_[A-Za-z0-9]{50,}`,
	"GitHub App Token":                       `(?i)(?:github|gh)[_-]?(?:app)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{40})`,

	// ============================================
	// GitLab
	// ============================================
	"GitLab Personal Access Token": `glpat-[A-Za-z0-9\-]{20,}`,
	"GitLab Pipeline Token":        `glptt-[A-Za-z0-9]{40}`,
	"GitLab Runner Token":          `GR1348941[A-Za-z0-9\-_]{20,}`,

	// ============================================
	// Slack
	// ============================================
	"Slack Bot Token":    `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
	"Slack User Token":   `xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
	"Slack App Token":    `xapp-[0-9]{1}-[A-Z0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{60,}`,
	"Slack Config Token": `xoxe\.xox[bp]-[0-9]{1}-[A-Z0-9]{160,}`,
	"Slack Refresh Token": `xoxe-[0-9]{1}-[A-Z0-9]{140,}`,
	"Slack Webhook URL":  `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`,

	// ============================================
	// Stripe
	// ============================================
	"Stripe Live Secret Key":      `sk_live_[0-9a-zA-Z]{24,}`,
	"Stripe Test Secret Key":      `sk_test_[0-9a-zA-Z]{24,}`,
	"Stripe Live Publishable Key": `pk_live_[0-9a-zA-Z]{24,}`,
	"Stripe Test Publishable Key": `pk_test_[0-9a-zA-Z]{24,}`,
	"Stripe Restricted Key":       `rk_live_[0-9a-zA-Z]{24,}`,
	"Stripe Webhook Secret":       `whsec_[0-9a-zA-Z]{32,}`,

	// ============================================
	// OpenAI / AI Services
	// ============================================
	"OpenAI API Key":     `sk-[A-Za-z0-9]{48}`,
	"OpenAI Project Key": `sk-proj-[A-Za-z0-9\-_]{80,}`,
	"Anthropic API Key":  `sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{80,}`,

	// ============================================
	// Discord
	// ============================================
	"Discord Bot Token":    `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`,
	"Discord Webhook URL":  `https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_-]{60,}`,

	// ============================================
	// Twilio
	// ============================================
	"Twilio Account SID": `AC[a-f0-9]{32}`,
	"Twilio Auth Token":  `(?i)(?:twilio)?[_-]?(?:auth)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{32})`,
	"Twilio API Key SID": `SK[a-f0-9]{32}`,

	// ============================================
	// SendGrid
	// ============================================
	"SendGrid API Key": `SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{40,}`,

	// ============================================
	// Mailgun
	// ============================================
	"Mailgun API Key":             `key-[0-9a-zA-Z]{32}`,
	"Mailgun Webhook Signing Key": `(?i)mailgun[_-]?(?:webhook[_-]?)?(?:signing[_-]?)?key['"\s]*[:=]['"\s]*([a-f0-9-]{36})`,

	// ============================================
	// Mailchimp
	// ============================================
	"Mailchimp API Key": `[a-f0-9]{32}-us[0-9]{1,2}`,

	// ============================================
	// NPM
	// ============================================
	"NPM Access Token": `npm_[A-Za-z0-9]{36}`,

	// ============================================
	// PyPI
	// ============================================
	"PyPI API Token": `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`,

	// ============================================
	// Heroku
	// ============================================
	"Heroku API Key": `(?i)heroku[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`,

	// ============================================
	// DigitalOcean
	// ============================================
	"DigitalOcean Personal Access Token": `dop_v1_[a-f0-9]{64}`,
	"DigitalOcean OAuth Token":           `doo_v1_[a-f0-9]{64}`,
	"DigitalOcean Refresh Token":         `dor_v1_[a-f0-9]{64}`,

	// ============================================
	// Azure
	// ============================================
	"Azure Storage Account Key": `(?i)(?:account)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9+/]{86}==)`,
	"Azure SAS Token":           `(?:sv=\d{4}-\d{2}-\d{2}&[^"']+sig=[A-Za-z0-9%+/=]{30,}|sig=[A-Za-z0-9%+/=]{40,}&sv=\d{4})`,
	"Azure Connection String":   `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};`,

	// ============================================
	// Shopify
	// ============================================
	"Shopify Access Token":     `shpat_[a-fA-F0-9]{24,}`,
	"Shopify Custom App Token": `shpca_[a-fA-F0-9]{24,}`,
	"Shopify Private App Token": `shppa_[a-fA-F0-9]{24,}`,
	"Shopify Shared Secret":    `shpss_[a-fA-F0-9]{24,}`,

	// ============================================
	// Square
	// ============================================
	"Square Access Token":  `sq0atp-[0-9A-Za-z\-_]{22}`,
	"Square OAuth Secret":  `sq0csp-[0-9A-Za-z\-_]{43}`,

	// ============================================
	// PayPal
	// ============================================
	"PayPal Braintree Access Token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"PayPal Client ID":              `paypal[Cc]lient[Ii]d\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"PayPal Client Secret":          `paypal[Cc]lient[Ss]ecret\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,

	// ============================================
	// Telegram
	// ============================================
	"Telegram Bot Token": `(?:bot)?[0-9]{9,10}:AA[A-Za-z0-9_-]{33}`,

	// ============================================
	// Facebook/Meta
	// ============================================
	"Facebook Access Token": `EAA[MC][a-zA-Z0-9]+`,
	"Facebook Client ID":    `(?i)(?:facebook|fb)[_-]?(?:app)?[_-]?(?:id|client)['"\s]*[:=]['"\s]*([0-9]{15,16})`,

	// ============================================
	// Twitter/X
	// ============================================
	"Twitter Bearer Token": `AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}`,
	"Twitter API Key":      `(?i)(?:twitter|tw)[_-]?(?:api)?[_-]?(?:key|consumer)['"\s]*[:=]['"\s]*([A-Za-z0-9]{25})`,
	"Twitter API Secret":   `(?i)(?:twitter|tw)[_-]?(?:api)?[_-]?(?:secret)['"\s]*[:=]['"\s]*([A-Za-z0-9]{50})`,

	// ============================================
	// LinkedIn
	// ============================================
	"LinkedIn Client ID":     `(?i)linkedin[_-]?(?:client)?[_-]?id['"\s]*[:=]['"\s]*([a-z0-9]{14})`,
	"LinkedIn Client Secret": `(?i)linkedin[_-]?(?:client)?[_-]?secret['"\s]*[:=]['"\s]*([A-Za-z0-9]{16})`,

	// ============================================
	// Datadog
	// ============================================
	"Datadog API Key":         `(?i)(?:datadog|dd)[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{32})`,
	"Datadog Application Key": `(?i)(?:datadog|dd)[_-]?(?:app(?:lication)?)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{40})`,

	// ============================================
	// New Relic
	// ============================================
	"New Relic API Key":      `NRAK-[A-Z0-9]{27}`,
	"New Relic License Key":  `[a-f0-9]{40}NRAL`,
	"New Relic Insights Key": `(?i)(?:new[_-]?relic|nr)[_-]?(?:insights?)?[_-]?key['"\s]*[:=]['"\s]*(NRI[A-Za-z0-9\-]{32})`,

	// ============================================
	// Sentry
	// ============================================
	"Sentry DSN":        `https://[a-f0-9]+@(?:[a-z0-9]+\.)?(?:ingest\.)?sentry\.io/[0-9]+`,
	"Sentry Auth Token": `(?i)sentry[_-]?(?:auth)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{64})`,

	// ============================================
	// PagerDuty
	// ============================================
	"PagerDuty API Key": `(?i)pagerduty[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9+_-]{20})`,

	// ============================================
	// Algolia
	// ============================================
	"Algolia API Key":   `(?i)(?:algolia[_-]?(?:api)?[_-]?key|algoliaApiKey|ALGOLIA_API_KEY)['"\s]*[:=]['"\s]*([a-f0-9]{32})`,
	"Algolia Admin Key": `(?i)algolia[_-]?(?:admin)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{32})`,

	// ============================================
	// Cloudflare
	// ============================================
	"Cloudflare API Key":   `(?i)cloudflare[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{37})`,
	"Cloudflare API Token": `(?i)cloudflare[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{40})`,

	// ============================================
	// Mapbox
	// ============================================
	"Mapbox Access Token": `pk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{20,}`,
	"Mapbox Secret Token": `sk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{20,}`,

	// ============================================
	// Database Connection Strings
	// ============================================
	"MongoDB Connection String":    `mongodb(?:\+srv)?://[^\s'"<>]+`,
	"PostgreSQL Connection String": `postgres(?:ql)?://[^\s'"<>]+`,
	"MySQL Connection String":      `mysql://[^\s'"<>]+`,
	"Redis Connection String":      `redis(?:s)?://[^\s'"<>]+`,

	// ============================================
	// JWT
	// ============================================
	"JSON Web Token": `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,

	// ============================================
	// Bearer Token
	// ============================================
	"Authorization Bearer Token": `(?i)(?:authorization|bearer)['"\s]*[:=]['"\s]*bearer\s+([A-Za-z0-9_\-\.]+)`,

	// ============================================
	// Private Keys
	// ============================================
	"RSA Private Key":       `-----BEGIN RSA PRIVATE KEY-----`,
	"OpenSSH Private Key":   `-----BEGIN OPENSSH PRIVATE KEY-----`,
	"DSA Private Key":       `-----BEGIN DSA PRIVATE KEY-----`,
	"EC Private Key":        `-----BEGIN EC PRIVATE KEY-----`,
	"PGP Private Key":       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"PEM Private Key":       `-----BEGIN PRIVATE KEY-----`,
	"Encrypted Private Key": `-----BEGIN ENCRYPTED PRIVATE KEY-----`,

	// ============================================
	// HashiCorp Vault
	// ============================================
	"Vault Token": `(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}`,

	// ============================================
	// Doppler
	// ============================================
	"Doppler API Token": `dp\.pt\.[a-zA-Z0-9]{43}`,

	// ============================================
	// Supabase
	// ============================================
	"Supabase API Key": `(?i)supabase[_-]?(?:key|anon|service)['"\s]*[:=]['"\s]*(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)`,

	// ============================================
	// Vercel
	// ============================================
	"Vercel Access Token": `(?i)vercel[_-]?(?:token|access)['"\s]*[:=]['"\s]*([A-Za-z0-9]{24})`,

	// ============================================
	// Netlify
	// ============================================
	"Netlify Access Token": `(?i)netlify[_-]?(?:token|access)['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{40,})`,

	// ============================================
	// CI/CD Tools
	// ============================================
	"CircleCI Personal Token": `(?i)circle[_-]?(?:ci)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{40})`,
	"Travis CI Token":         `(?i)travis[_-]?(?:ci)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9]{22})`,
	"Jenkins API Token":       `(?i)jenkins[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{32,})`,
	"SonarQube Token":         `sqp_[a-f0-9]{40}`,

	// ============================================
	// Grafana
	// ============================================
	"Grafana API Key":              `eyJrIjoi[A-Za-z0-9_-]{50,}`,
	"Grafana Service Account Token": `glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`,

	// ============================================
	// Pulumi
	// ============================================
	"Pulumi Access Token": `pul-[a-f0-9]{40}`,

	// ============================================
	// Contentful
	// ============================================
	"Contentful Delivery Token": `(?i)contentful[_-]?(?:delivery)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{43})`,

	// ============================================
	// HubSpot
	// ============================================
	"HubSpot API Key":           `(?i)hubspot[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,
	"HubSpot Private App Token": `pat-(?:na|eu)1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,

	// ============================================
	// Intercom
	// ============================================
	"Intercom Access Token": `(?i)intercom[_-]?(?:access)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9=]{60,})`,

	// ============================================
	// Zendesk
	// ============================================
	"Zendesk API Token": `(?i)zendesk[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9]{40})`,

	// ============================================
	// Asana
	// ============================================
	"Asana Personal Access Token": `[0-9]/[0-9]{16}:[A-Za-z0-9]{32}`,

	// ============================================
	// Jira/Atlassian
	// ============================================
	"Jira API Token":      `(?i)jira[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9]{24})`,
	"Atlassian API Token": `(?i)atlassian[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9]{24})`,

	// ============================================
	// Okta
	// ============================================
	"Okta API Token": `(?i)okta[_-]?(?:api)?[_-]?token['"\s]*[:=]['"\s]*00[A-Za-z0-9_-]{40}`,

	// ============================================
	// Auth0
	// ============================================
	"Auth0 Management API Token": `(?i)auth0[_-]?(?:mgmt|management)?[_-]?token['"\s]*[:=]['"\s]*(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)`,

	// ============================================
	// Plaid
	// ============================================
	"Plaid Client ID": `(?i)plaid[_-]?(?:client)?[_-]?id['"\s]*[:=]['"\s]*([a-f0-9]{24})`,
	"Plaid Secret":    `(?i)plaid[_-]?(?:secret)['"\s]*[:=]['"\s]*([a-f0-9]{30})`,

	// ============================================
	// Braintree
	// ============================================
	"Braintree Access Token": `access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}`,

	// ============================================
	// Crypto
	// ============================================
	"Coinbase API Key": `(?i)coinbase[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9]{16})`,
	"Binance API Key":  `(?i)binance[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9]{64})`,
	"Infura API Key":   `(?i)infura[_-]?(?:api)?[_-]?(?:key|id)['"\s]*[:=]['"\s]*([a-f0-9]{32})`,
	"Alchemy API Key":  `(?i)alchemy[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{32})`,

	// ============================================
	// Airtable
	// ============================================
	"Airtable API Key":              `["']?(key[A-Za-z0-9]{14})["']`,
	"Airtable Personal Access Token": `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`,

	// ============================================
	// Notion
	// ============================================
	"Notion Integration Token": `secret_[A-Za-z0-9]{43}`,

	// ============================================
	// Linear
	// ============================================
	"Linear API Key": `lin_api_[A-Za-z0-9]{40}`,

	// ============================================
	// Figma
	// ============================================
	"Figma Personal Access Token": `figd_[A-Za-z0-9_-]{40,}`,

	// ============================================
	// Lark/Feishu
	// ============================================
	"Lark/Feishu App Secret": `(?i)(?:lark|feishu)[_-]?(?:app)?[_-]?secret['"\s]*[:=]['"\s]*([A-Za-z0-9]{32})`,

	// ============================================
	// Dynatrace
	// ============================================
	"Dynatrace API Token": `dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}`,

	// ============================================
	// Splunk
	// ============================================
	"Splunk HEC Token": `(?i)splunk[_-]?(?:hec)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,

	// ============================================
	// Elasticsearch
	// ============================================
	"Elasticsearch API Key": `(?i)elastic(?:search)?[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{20,})`,

	// ============================================
	// LaunchDarkly
	// ============================================
	"LaunchDarkly SDK Key": `sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
	"LaunchDarkly API Key": `api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,

	// ============================================
	// PostHog
	// ============================================
	"PostHog API Key": `phc_[A-Za-z0-9]{32,}`,

	// ============================================
	// Mixpanel
	// ============================================
	"Mixpanel Project Token": `(?i)mixpanel[_-]?(?:project)?[_-]?token['"\s]*[:=]['"\s]*([a-f0-9]{32})`,

	// ============================================
	// Amplitude
	// ============================================
	"Amplitude API Key": `(?i)amplitude[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{32})`,

	// ============================================
	// Segment
	// ============================================
	"Segment Write Key": `(?i)segment[_-]?(?:write)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9]{32})`,

	// ============================================
	// Twitch
	// ============================================
	"Twitch Client ID":   `(?i)twitch[_-]?(?:client)?[_-]?id['"\s]*[:=]['"\s]*([a-z0-9]{30})`,
	"Twitch OAuth Token": `oauth:[a-z0-9]{30}`,

	// ============================================
	// YouTube
	// ============================================
	"YouTube API Key": `(?i)youtube[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*(AIza[0-9A-Za-z\-_]{35})`,

	// ============================================
	// Spotify
	// ============================================
	"Spotify Client ID":     `(?i)spotify[_-]?(?:client)?[_-]?id['"\s]*[:=]['"\s]*([a-f0-9]{32})`,
	"Spotify Client Secret": `(?i)spotify[_-]?(?:client)?[_-]?secret['"\s]*[:=]['"\s]*([a-f0-9]{32})`,

	// ============================================
	// Zoom
	// ============================================
	"Zoom JWT Token": `(?i)zoom[_-]?(?:jwt)?[_-]?token['"\s]*[:=]['"\s]*(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)`,

	// ============================================
	// DocuSign
	// ============================================
	"DocuSign Integration Key": `(?i)docusign[_-]?(?:integration)?[_-]?key['"\s]*[:=]['"\s]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,

	// ============================================
	// Dropbox
	// ============================================
	"Dropbox Access Token":      `sl\.[A-Za-z0-9_-]{130,}`,
	"Dropbox Short-Lived Token": `(?i)dropbox[_-]?(?:access)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{64,})`,

	// ============================================
	// Box
	// ============================================
	"Box Access Token": `(?i)box[_-]?(?:access)?[_-]?token['"\s]*[:=]['"\s]*([A-Za-z0-9]{32})`,

	// ============================================
	// Microsoft
	// ============================================
	"Microsoft Graph Access Token": `EwB[A-Za-z0-9_-]{50,}`,

	// ============================================
	// Salesforce
	// ============================================
	"Salesforce Access Token":  `00D[a-zA-Z0-9]{15}![A-Za-z0-9_.]{80,}`,
	"Salesforce Refresh Token": `5Aep861[A-Za-z0-9._]{80,}`,

	// ============================================
	// SAP
	// ============================================
	"SAP API Key": `(?i)sap[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9]{32})`,

	// ============================================
	// Fastly
	// ============================================
	"Fastly API Key": `(?i)fastly[_-]?(?:api)?[_-]?key['"\s]*[:=]['"\s]*([A-Za-z0-9_-]{32})`,

	// ============================================
	// Cloudinary
	// ============================================
	"Cloudinary URL": `cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+`,

	// ============================================
	// Google Docs/Sheets/Drive URLs
	// ============================================
	"Google Docs URL":        `https://docs\.google\.com/document/d/[a-zA-Z0-9_-]+`,
	"Google Sheets URL":      `https://docs\.google\.com/spreadsheets/d/[a-zA-Z0-9_-]+`,
	"Google Drive URL":       `https://drive\.google\.com/(?:file/d/|open\?id=|drive/folders/)[a-zA-Z0-9_-]+`,
	"Google Forms URL":       `https://docs\.google\.com/forms/d/[a-zA-Z0-9_-]+`,
	"Google Slides URL":      `https://docs\.google\.com/presentation/d/[a-zA-Z0-9_-]+`,

	// ============================================
	// JS CamelCase Patterns (for minified files)
	// ============================================
	"JS clientId":        `["']?clientId["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS clientSecret":    `["']?clientSecret["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS apiKey":          `["']?apiKey["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS apiSecret":       `["']?apiSecret["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS secretKey":       `["']?secretKey["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS accessToken":     `["']?accessToken["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS authToken":       `["']?authToken["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS privateKey":      `["']?privateKey["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS refreshToken":    `["']?refreshToken["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS bearerToken":     `["']?bearerToken["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS appId":           `["']?appId["']?\s*[,:]\s*["']([A-Za-z0-9_-]{15,})["']`,
	"JS appSecret":       `["']?appSecret["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS appKey":          `["']?appKey["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS consumerKey":     `["']?consumerKey["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
	"JS consumerSecret":  `["']?consumerSecret["']?\s*[,:]\s*["']([A-Za-z0-9_-]{20,})["']`,
}

// GenericSecretKeywords for key-value extraction
var GenericSecretKeywords = []string{
	// API Keys
	"apikey", "api_key", "api-key", "apiKey",
	"api_secret", "apisecret", "apiSecret", "api-secret",

	// Tokens
	"token", "access_token", "accesstoken", "accessToken", "access-token",
	"auth_token", "authtoken", "authToken", "auth-token",
	"bearer_token", "bearertoken", "bearerToken", "bearer-token",
	"refresh_token", "refreshtoken", "refreshToken", "refresh-token",
	"id_token", "idtoken", "idToken", "id-token",
	"session_token", "sessiontoken", "sessionToken", "session-token",

	// Secrets
	"secret", "secret_key", "secretkey", "secretKey", "secret-key",
	"client_secret", "clientsecret", "clientSecret", "client-secret",
	"app_secret", "appsecret", "appSecret", "app-secret",

	// Passwords
	"password", "passwd", "pwd", "pass",

	// Keys
	"private_key", "privatekey", "privateKey", "private-key",
	"public_key", "publickey", "publicKey", "public-key",
	"encryption_key", "encryptionkey", "encryptionKey", "encryption-key",
	"signing_key", "signingkey", "signingKey", "signing-key",

	// Service-specific keywords
	"github_token", "githubtoken", "githubToken", "github-token",
	"gitlab_token", "gitlabtoken", "gitlabToken", "gitlab-token",
	"aws_key", "awskey", "awsKey", "aws-key",
	"aws_secret", "awssecret", "awsSecret", "aws-secret",
	"stripe_key", "stripekey", "stripeKey", "stripe-key",
	"slack_token", "slacktoken", "slackToken", "slack-token",
	"discord_token", "discordtoken", "discordToken", "discord-token",
	"firebase_key", "firebasekey", "firebaseKey", "firebase-key",
	"google_key", "googlekey", "googleKey", "google-key",
	"openai_key", "openaikey", "openaiKey", "openai-key",
	"database_url", "databaseurl", "databaseUrl", "database-url",
	"db_password", "dbpassword", "dbPassword", "db-password",
	"redis_url", "redisurl", "redisUrl", "redis-url",
	"mongo_uri", "mongouri", "mongoUri", "mongo-uri",

	// Credentials
	"credentials", "creds", "auth", "authorization",
	"client_id", "clientid", "clientId", "client-id",
	"app_id", "appid", "appId", "app-id",
	"consumer_key", "consumerkey", "consumerKey", "consumer-key",
	"consumer_secret", "consumersecret", "consumerSecret", "consumer-secret",
}

// FalsePositiveIndicators - skip matches containing these
var FalsePositiveIndicators = []string{
	"cdn-cgi",
	"challenge-platform",
	"cloudflare",
	"__WEBPACK__",
	"sourceMappingURL",
	"function(",
	".prototype",
	"Object.defineProperty",
	"===",
	"return ",
	"undefined",
	"null",
	".exec)",
	"RegExp",
	// Base64 PNG/image indicators (common false positives for bearer tokens)
	"SuQmCC",    // PNG end marker in base64
	"ElFTkS",    // PNG end marker in base64 (IEND chunk)
	"AAAAAAA",   // Repeated null bytes in base64 (common in images)
	"CYII",      // Another PNG end marker variant
	// i18n/localization key indicators
	".strength.",
	".unsafepwd",
	".tooshortpwd",
	"password.",
}

// SkipValues - values that are clearly not secrets
var SkipValues = []string{
	"null", "undefined", "true", "false", "none", "",
	"0", "1", "test", "example", "placeholder", "your-",
	"xxx", "yyy", "zzz", "abc", "123", "TODO", "FIXME",
	"process.env", "window.", "document.", "this.",
	"dummy", "sample", "fake", "mock", "demo",
	"test_", "example_", "sample_", "demo_",
	"INSERT", "REPLACE", "YOUR_", "ENTER_", "<YOUR",
	"xxxxxxxx", "00000000", "11111111", "12345678",
	"password123", "password1", "changeme", "secret123",
	"1234567890", "abcdefgh", "qwerty",
}

// TestFileIndicators - patterns that indicate test/example data
var TestFileIndicators = []string{
	"test", "example", "sample", "demo", "dummy", "fake", "mock",
	"placeholder", "template", "skeleton", "stub", "fixture",
	"DO_NOT_USE", "OLD_KEY", "DEPRECATED", "EXAMPLE",
}
