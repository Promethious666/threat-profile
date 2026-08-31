# Threat Profile Workbench

Threat Profile turns a small amount of organisational context into an evidence-led cyber threat intelligence brief. Choose a sector and country, optionally add technology keywords, and the workbench helps an analyst answer:

> Which public threat intelligence is most relevant to this operating context, what should we investigate first, and where are the evidence gaps?

The site is intentionally careful with language. It ranks **profile fit**, not attack likelihood; keeps source evidence visible; and never presents a keyword match as confirmed exposure.

## What makes it useful

- **Decision-first overview:** key judgements and priority actions appear before long data lists.
- **Explainable actor ranking:** sector and country matches are adjusted for how broad each actor record is.
- **Controllable analysis focus:** choose Top 5, 10, 15, 20 or 25 actors. Every score tie at the boundary is retained, and techniques, software, campaigns, KQL priorities and exports are recalculated from the chosen cohort.
- **Honest dated windows:** choose 1 week, 2 weeks, 1, 3, 6, 12, 24 or 36 months, or all available dated evidence. Campaigns use ATT&CK `last_seen`, KEV uses CISA `dateAdded`, and current signals use source publication dates.
- **Complete exploration:** search, filters, progressive result loading, actor and technique detail, and full exports keep every profile match available even when it sits outside the analytical focus.
- **Current threat signals:** provenance-reviewed evidence surfaces Scattered Spider and ShinyHunters as threat actor groups and Qilin correctly as a ransomware family, with sector/country claims kept independent unless a source proves their intersection.
- **Source-backed relationships:** ATT&CK descriptions, campaigns, procedures, dates and references are retained through normalisation.
- **Operational KQL:** ten Microsoft Sentinel and Defender XDR hunting starters include their target product, tables, prerequisites, false positives, tuning advice, validation steps and official Microsoft schema links.
- **Careful KEV triage:** technology keywords create a possible environment match; they do not confirm that an asset exists or is vulnerable.
- **Honest analytic models:** the Diamond Model and Pyramid of Pain show missing evidence instead of filling gaps with assumptions.
- **Portable outputs:** export the complete profile—including active scope and excluded dated evidence—as JSON, or open the recalculated techniques in ATT&CK Navigator.
- **Decision-ready reports:** print or save a concise management and audit report as PDF directly from the browser.

Organisation names are display context only and are deliberately excluded from share links. The browser sends no profile data to an application server because the site is fully static.

## Quick start

1. Select the sector and country. Organisation and technology are optional private context.
2. Choose a dated evidence window. This affects only records with a defensible date; undated historical actor context remains visible and labelled.
3. Choose the Top-N analysis focus. A larger cohort broadens the techniques, software, campaigns and KQL priorities considered.
4. Review the dated signals first, then validate actor evidence, hunts and KEV context.
5. Share the privacy-safe URL or export JSON, ATT&CK Navigator and a printable PDF report. Window and focus settings are preserved in shared links and reports.

## Intelligence sources

The scheduled workflow refreshes three public structured sources every six hours:

- [MITRE ATT&CK Enterprise STIX](https://github.com/mitre-attack/attack-stix-data)
- [MISP Galaxy Tidal Groups](https://github.com/MISP/misp-galaxy/blob/main/clusters/tidal-groups.json)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Every refresh records retrieval time, source version where available, record count, content hash and source status. New snapshots must clear minimum coverage checks and a large-regression guard. If an upstream refresh fails, the workflow can reuse a validated last-known-good snapshot and marks it stale in the interface.

The separate current-signal layer is deliberately curated rather than scraped or generated automatically. Each record retains a reviewed authoritative source, entity type, publication date, independent sector/country claims and explicit caveats. It is schema-validated and deployed by the same free GitHub Actions workflow, but adding or changing a signal requires human review. This avoids turning an unverified headline feed into a targeting claim.

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

The Pages workflow runs on pushes to `main`, manual dispatch and every six hours. It refreshes the three structured intelligence sources, validates the curated signal layer, runs tests, builds the static artifact, then deploys it using GitHub Pages and GitHub Actions at no application-hosting cost.

GitHub automatically disables scheduled workflows in a public repository after 60 days with no repository activity. If that happens, re-enable the Pages workflow from the repository's **Actions** tab; a push or manual run also rebuilds the site. The interface exposes snapshot timestamps and source status so a paused refresh is visible rather than silently described as current.

After creating the repository, select **Settings → Pages → Build and deployment → Source → GitHub Actions** once. Pull requests run the separate validation workflow without deploying.

## Boundaries

This is a prioritisation aid for analysts, not an automated attribution system, risk score, exposure scanner, or substitute for organisation-specific intelligence. Review [SECURITY.md](SECURITY.md) before adding any private source.
