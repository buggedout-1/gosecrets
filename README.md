# GoSecrets

```
    ╔═══════════════════════════════════════════════════════════════════╗
    ║   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ║
    ║     ██████╗  ██████╗       ███████╗███████╗ ██████╗               ║
    ║    ██╔════╝ ██╔═══██╗      ██╔════╝██╔════╝██╔════╝               ║
    ║    ██║  ███╗██║   ██║█████╗███████╗█████╗  ██║                    ║
    ║    ██║   ██║██║   ██║╚════╝╚════██║██╔══╝  ██║                    ║
    ║    ╚██████╔╝╚██████╔╝      ███████║███████╗╚██████╗               ║
    ║     ╚═════╝  ╚═════╝       ╚══════╝╚══════╝ ╚═════╝               ║
    ║   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀        ║
    ║              ░▒▓ Go Secrets Scanner ▓▒░                           ║
    ║     Extract API keys, tokens & credentials from files             ║
    ║     Version: 1.0.0                                                ║
    ╚═══════════════════════════════════════════════════════════════════╝
```

A fast, concurrent secrets scanner written in Go. Extracts API keys, tokens, credentials, and other sensitive data from JavaScript files and web content.

## Features

- **180+ regex patterns** for detecting secrets from popular services
- **Concurrent scanning** with configurable worker pools
- **Low false positive rate** with intelligent filtering
- **JSON output** for easy integration with other tools
- **Single binary** - no dependencies required

## Supported Secret Types

| Category | Services |
|----------|----------|
| **Cloud Providers** | AWS, Google Cloud, Azure, DigitalOcean, Heroku |
| **Payment** | Stripe, PayPal, Square, Braintree |
| **Communication** | Slack, Discord, Twilio, SendGrid, Mailgun, Mailchimp |
| **Version Control** | GitHub, GitLab |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis |
| **Analytics** | New Relic, Sentry, Datadog, Mixpanel, Amplitude |
| **CMS/Services** | Shopify, Contentful, Supabase, Firebase |
| **CI/CD** | CircleCI, Travis CI, Jenkins |
| **Auth** | Auth0, Okta, JWT tokens |
| **And more...** | Mapbox, Cloudinary, Algolia, Zendesk, etc. |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/gosecrets.git
cd gosecrets

# Build
go build -o gosecrets .

# Or install directly
go install .
```

### Pre-built Binary

Download the latest release from the [Releases](https://github.com/yourusername/gosecrets/releases) page.

## Usage

```bash
# Basic usage
gosecrets -l urls.txt

# With custom output file
gosecrets -l urls.txt -o results.json

# Increase workers for faster scanning
gosecrets -l urls.txt -w 50

# Silent mode (minimal output)
gosecrets -l urls.txt -s

# Verbose mode (show errors)
gosecrets -l urls.txt -v
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l` | Path to file containing URLs to scan (required) | - |
| `-o` | Output JSON file | `secrets.json` |
| `-w` | Number of concurrent workers | `30` |
| `-t` | HTTP timeout in seconds | `15` |
| `-s` | Silent mode (minimal output) | `false` |
| `-v` | Verbose output (show errors) | `false` |

### Input File Format

Create a text file with one URL per line:

```
https://example.com/app.js
https://example.com/bundle.min.js
https://cdn.example.com/scripts/main.js
```

### Output Format

Results are saved in JSON format:

```json
[
    {
        "url": "https://example.com/app.js",
        "secrets": {
            "AWS Access Key ID": ["AKIAIOSFODNN7EXAMPLE"],
            "Stripe Live Secret Key": ["sk_live_..."],
            "JSON Web Token": ["eyJhbGciOiJIUzI1NiIs..."]
        }
    }
]
```

## Integration with Recon Pipeline

GoSecrets is designed to work with subdomain enumeration and URL discovery tools:

```bash
# Example pipeline
cat subdomains.txt | httpx -silent | katana -silent | grep -E '\.(js|json|config)$' > urls.txt
gosecrets -l urls.txt -w 50 -o secrets.json
```

## False Positive Filtering

GoSecrets includes intelligent filtering to reduce false positives:

- **Test/Example detection** - Filters keys containing "EXAMPLE", "test", "sample", etc.
- **UUID filtering** - Ignores standard UUID formats (except for services that use them)
- **Hash detection** - Skips SHA1/SHA256 hashes that look like tokens
- **Code pattern filtering** - Ignores JavaScript code patterns and minified variable names
- **reCAPTCHA filtering** - Skips public reCAPTCHA site keys

## Performance

| Metric | Value |
|--------|-------|
| URLs/second | ~50-100 (depends on network) |
| Memory usage | ~50MB |
| CPU usage | Scales with worker count |

Recommended settings for different scenarios:

```bash
# Standard VPS (2-4 cores)
gosecrets -l urls.txt -w 30

# High-performance VPS (8+ cores)
gosecrets -l urls.txt -w 100

# Rate-limited targets
gosecrets -l urls.txt -w 10 -t 30
```

## Contributing

Contributions are welcome! To add new patterns:

1. Edit `patterns.go`
2. Add your regex to `DefaultPatterns` map
3. Test against known samples
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [truffleHog](https://github.com/trufflesecurity/trufflehog) and [gitleaks](https://github.com/gitleaks/gitleaks)
- Regex patterns compiled from various security research sources
