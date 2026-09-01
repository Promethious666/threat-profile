# Threat Profile Workbench

Threat Profile turns a small amount of organisational context into an evidence-led OSINT brief. Choose a sector and country, optionally add organisation aliases, technology keywords or an actor watchlist, and the workbench helps an analyst answer:

> Which public threat intelligence is most relevant to this operating context, what should we investigate first, and where are the evidence gaps?

The site is intentionally careful with language. It ranks **profile fit**, not attack likelihood; keeps source evidence visible; and never presents a keyword match as confirmed exposure.

## What makes it useful

- **Report-first overview:** automatically collected public reporting, key judgements and actions appear before historical data lists.
- **Explainable actor ranking:** sector and country matches are adjusted for how broad each actor record is.
- **Controllable analysis focus:** choose Top 5, 10, 15, 20 or 25 actors. Every score tie at the boundary is retained, and techniques, software, campaigns, KQL priorities and exports are recalculated from the chosen cohort.
- **Honest dated windows:** choose 1 week, 2 weeks, 1, 3, 6, 12, 24 or 36 months, or all available dated evidence. Public reports use source publication dates, campaigns use ATT&CK `last_seen`, and KEV uses CISA `dateAdded`.
- **Complete exploration:** search, filters, progressive result loading, actor and technique detail, and full exports keep every profile match available even when it sits outside the analytical focus.
- **Automated discovery:** government and vendor threat-research feeds are collected every six hours. Reports are matched from their own text, and country-only mentions never create sector relevance.
- **Clear campaign handling:** a current report is labelled campaign reporting only when its source describes a campaign or named operation; ATT&CK campaigns remain historical context.
- **Source-backed relationships:** ATT&CK descriptions, campaigns, procedures, dates and references are retained through normalisation.
- **Operational KQL:** ten Microsoft Sentinel and Defender XDR hunting starters include their target product, tables, prerequisites, false positives, tuning advice, validation steps and official Microsoft schema links.
- **Careful KEV triage:** technology keywords create a possible environment match; they do not confirm that an asset exists or is vulnerable.
- **Honest analytic models:** the Diamond Model and Pyramid of Pain show missing evidence instead of filling gaps with assumptions.
- **Portable outputs:** export the complete profile—including active scope and excluded dated evidence—as JSON, or open the recalculated techniques in ATT&CK Navigator.
- **Decision-ready reports:** print or save a concise management and audit report as PDF directly from the browser.

Organisation, technology and watchlist terms are matched locally in the browser and deliberately excluded from share links. The browser sends no profile data to an application server because the site is fully static.

## Quick start

1. Select the sector and country. Organisation aliases, technology and watchlist terms are optional private context.
2. Choose a dated evidence window. This affects only records with a defensible date; undated historical actor context remains visible and labelled.
3. Choose the Top-N analysis focus. A larger cohort broadens the techniques, software, campaigns and KQL priorities considered.
4. Review the current public reports first, then use historical actors, hunts and KEV as supporting context.
5. Share the privacy-safe URL or export JSON, ATT&CK Navigator and a printable PDF report. Window and focus settings are preserved in shared links and reports.

## Intelligence sources

The scheduled workflow refreshes seven public sources every six hours. Three provide structured context:

- [MITRE ATT&CK Enterprise STIX](https://github.com/mitre-attack/attack-stix-data)
- [MISP Galaxy Tidal Groups](https://github.com/MISP/misp-galaxy/blob/main/clusters/tidal-groups.json)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Four provide dated public reporting for current triage:

- [UK NCSC Threat Reports](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports)
- [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/)

Every refresh records retrieval time, source version where available, record count, content hash and source status. New structured snapshots must clear minimum coverage and regression guards. Public reports retain only a bounded summary, publication date and original link; matching is deterministic and visible. If an upstream refresh fails, the workflow can reuse a validated last-known-good snapshot and marks it stale in the interface.

## KQL assurance level

The included queries are labelled **Schema reviewed · Tenant validation required**. Their table and column logic is reviewed against official Microsoft Learn documentation, but licensing, connectors, local field population, baselines and false positives vary by tenant. Treat them as transparent hunting starters, validate them in your environment, and only then promote suitably structured queries into scheduled analytics or custom detections.

See [KQL-GUIDE.md](KQL-GUIDE.md) for the review checklist and [METHODOLOGY.md](METHODOLOGY.md) for the scoring and evidence model.

## Run locally

Install Node.js 22 or later. There are no runtime packages to install.

```bash
npm run update:intelligence
npm test
npm run lint
npm run build
npm run dev
```

Open the local address printed by the development server. The intelligence update needs network access; the built site itself does not.

## GitHub Pages

The Pages workflow runs on pushes to `main`, manual dispatch and every six hours. It refreshes all seven intelligence sources, validates the data, runs tests, builds the static artifact, then deploys it using GitHub Pages and GitHub Actions at no application-hosting cost.

GitHub automatically disables scheduled workflows in a public repository after 60 days with no repository activity. If that happens, re-enable the Pages workflow from the repository's **Actions** tab; a push or manual run also rebuilds the site. The interface exposes snapshot timestamps and source status so a paused refresh is visible rather than silently described as current.

After creating the repository, select **Settings → Pages → Build and deployment → Source → GitHub Actions** once. Pull requests run the separate validation workflow without deploying.

## Boundaries

This is a prioritisation aid for analysts, not an automated attribution system, risk score, exposure scanner, or substitute for organisation-specific intelligence. Review [SECURITY.md](SECURITY.md) before adding any private source.
