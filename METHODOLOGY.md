# Methodology

## Assessment language

Threat Profile produces a **profile relevance inference** from public historical metadata. It does not estimate probability, declare a threat actor active, attribute an incident, or prove that a named organisation was targeted.

The interface keeps two ideas separate:

- **Profile fit** describes how specifically an actor record matches the selected sector and country.
- **Analytic confidence** describes the strength and timeliness of the supporting targeting evidence.

The current targeting source is an undated aggregate, so matched actors are labelled **Low analytic confidence** regardless of their profile-fit score. Multiple source references improve traceability; they do not automatically increase confidence.

## Actor profile fit

Sector and country each contribute up to 50 points. A match is discounted when the actor record spans many values in that dimension:

```text
specificity(breadth, universe) = log2(universe / breadth) / log2(universe)
profile fit = 50 × sector specificity + 50 × country specificity
```

`breadth` is the number of recorded values for that actor and `universe` is the number of values present in the current validated dataset. Specificity is constrained to 0–1.

This prevents an actor tagged for almost every sector or country from outranking an actor with much narrower context. The displayed bands are:

- **Focused match:** 70–100
- **Material match:** 40–69.9
- **Broad match:** below 40

Exact score ties use competition ranking (`1, 1, 3`) and a stable ATT&CK ID order for display only. The workbench does not silently break a tie or automatically choose a Diamond Model actor.

Sector and country attributes may come from different historical observations. Therefore every result explicitly sets joint targeting evidence to false; matching both dimensions is not a claim that the source observed them together.

## Techniques and software

ATT&CK techniques are aggregated across profile-matched actors. The technique score is the lower of:

1. profile-fit-weighted actor coverage; and
2. coverage after each actor's contribution is reduced by the square root of that actor's documented technique count.

Using the lower value avoids allowing heavily documented actors to dominate the ranking merely because they have more ATT&CK relationships. Mapping completeness is shown separately because an actor with no technique relationships cannot contribute to technique coverage.

The default defensive view excludes Reconnaissance and Resource Development from operational technique recommendations while retaining those techniques in the complete data and exports.

Software coverage is descriptive ATT&CK relationship context. It is not proof that a tool is currently in use.

## Campaign recency

Campaigns appear only when ATT&CK links them to a profile-matched actor. Profile fit and recency remain separate values.

Recency uses `last_seen` only. It never substitutes the STIX object's `modified` timestamp, because a record update is not activity. When a valid `last_seen` exists, the display uses a two-year half-life:

```text
recency = 100 × 2 ^ (−age in days / 730)
```

Missing or future dates produce an unknown recency state. A recent date does not prove that a campaign is still active.

## Vulnerability context

CISA KEV confirms that a vulnerability has been exploited in the wild. It does not confirm that the selected organisation runs the product.

- With no technology terms, KEV entries are labelled **Exposure unknown**.
- A vendor, product, vulnerability-name or CVE keyword match is labelled **Possible environment match**.
- The workbench never produces **Confirmed exposure**, because it has no asset inventory or vulnerability scan.

An analyst should confirm product presence, affected versions, control coverage and remediation state outside this site.

## Diamond Model

The Diamond view is an actor-scoped, partial relationship frame:

- **Adversary:** an actor explicitly selected by the analyst.
- **Capability:** ATT&CK techniques and software associated with that actor.
- **Victim context:** the selected sector and country, clearly labelled as profile context rather than a direct victim assertion.
- **Infrastructure:** marked not collected.

It is not presented as a complete event because the source set lacks an event-level link joining adversary, capability, infrastructure and victim.

## Pyramid of Pain

The Pyramid view is a collection-coverage inventory. ATT&CK techniques and tools can be populated from the current sources. Hashes, IP addresses, domains and host/network artefacts are marked not collected; no operational indicator is inferred from prose.

## Source provenance and freshness

Normalisation retains assertion-level URLs where the upstream structured record provides them, as well as actor descriptions, ATT&CK relationship procedures, object dates, targeting owners and record identifiers. The site distinguishes:

- **retrieval freshness:** when the public source snapshot was successfully downloaded; and
- **observation recency:** when the underlying activity was observed, if the source supplies that date.

An undated historical targeting attribute does not become current simply because its source file was refreshed today.
