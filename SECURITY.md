# Security

## Supported version

Security fixes are applied to the current `main` branch and the live GitHub Pages deployment. Older exports and downloaded copies are not maintained.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Promethious666/threat-profile/security/advisories/new). Include the affected URL or file, impact, reproduction steps and any suggested mitigation. Do not open a public issue containing exploit details, credentials, sensitive URLs or customer information.

## Data and privacy boundary

Threat Profile is a public-source intelligence tool served as a static site. It has no application server, account system or browser-side API keys, and profile text is not sent to an application backend.

Organisation and technology text are excluded from generated share links and ATT&CK Navigator exports. Printable reports and complete JSON exports intentionally include entered context so the assessment remains useful; review those local files before sharing them.

Do not commit or publish:

- API keys, tokens or credentials;
- private intelligence reports or customer data;
- internal indicators, asset inventories or investigation notes;
- organisation names or technology context that is not approved for disclosure.

If private sources are added later, collect them in a controlled workflow, keep credentials in repository or environment secrets, minimise the published fields, and complete a disclosure review before deployment.

## Application and deployment controls

- GitHub Pages enforces HTTPS on the default domain.
- A restrictive Content Security Policy and `no-referrer` policy limit browser resource loading and outbound referrer data.
- The GitHub Pages environment accepts deployments from `main` only; the build job is read-only and does not retain checkout credentials.
- GitHub Actions are pinned to immutable commit SHAs and tracked by Dependabot.
- GitHub CodeQL, dependency alerts, security updates, malware alerts, secret scanning and push protection are enabled for the public repository.
- Private vulnerability reporting provides a non-public disclosure path.

GitHub Pages does not allow this repository to set arbitrary HTTP response headers. The in-document policy therefore cannot provide header-only controls such as CSP `frame-ancestors`; that platform limitation is not presented as covered.

## Upstream intelligence

Upstream data is treated as untrusted input. The refresh process parses and validates it, applies minimum coverage and regression guards, and retains a validated last-known-good snapshot when a refresh fails. The interface escapes rendered values, accepts only valid HTTPS evidence links and labels stale or incomplete evidence. These controls reduce risk but do not turn public feeds into trusted internal intelligence.
