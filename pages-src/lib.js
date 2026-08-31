const OPERATIONAL_TACTICS = new Set([
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
]);

export const EVIDENCE_WINDOW_PRESETS = Object.freeze({
  "7d": Object.freeze({ key: "7d", label: "1 week", days: 7 }),
  "14d": Object.freeze({ key: "14d", label: "2 weeks", days: 14 }),
  "1m": Object.freeze({ key: "1m", label: "1 month", months: 1 }),
  "3m": Object.freeze({ key: "3m", label: "3 months", months: 3 }),
  "6m": Object.freeze({ key: "6m", label: "6 months", months: 6 }),
  "12m": Object.freeze({ key: "12m", label: "12 months", months: 12 }),
  "24m": Object.freeze({ key: "24m", label: "24 months", months: 24 }),
  "36m": Object.freeze({ key: "36m", label: "36 months", months: 36 }),
  all: Object.freeze({ key: "all", label: "All available" }),
});

export const TOP_FOCUS_VALUES = Object.freeze([5, 10, 15, 20, 25]);

const EVIDENCE_WINDOW_ALIASES = new Map([
  ["7d", "7d"], ["7 days", "7d"], ["1w", "7d"], ["1 week", "7d"], ["week", "7d"],
  ["14d", "14d"], ["14 days", "14d"], ["2w", "14d"], ["2 weeks", "14d"],
  ["1m", "1m"], ["1 month", "1m"], ["month", "1m"],
  ["3m", "3m"], ["3 months", "3m"],
  ["6m", "6m"], ["6 months", "6m"],
  ["12m", "12m"], ["12 months", "12m"], ["1y", "12m"], ["1 year", "12m"],
  ["24m", "24m"], ["24 months", "24m"], ["2y", "24m"], ["2 years", "24m"],
  ["36m", "36m"], ["36 months", "36m"], ["3y", "36m"], ["3 years", "36m"],
  ["all", "all"], ["all available", "all"],
]);

function normaliseString(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ");
}

export function normalizeEvidenceWindowPreset(value, fallback = "24m") {
  const candidate = typeof value === "object" && value !== null ? value.key : value;
  const normalized = EVIDENCE_WINDOW_ALIASES.get(normaliseString(candidate));
  if (normalized) return normalized;

  const fallbackCandidate = typeof fallback === "object" && fallback !== null ? fallback.key : fallback;
  return EVIDENCE_WINDOW_ALIASES.get(normaliseString(fallbackCandidate)) || "24m";
}

function parseDate(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const calendarDate = /^(\d{4})-(\d{2})-(\d{2})(?:$|T)/.exec(trimmed);
    if (calendarDate) {
      const [, year, month, day] = calendarDate.map(Number);
      const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
      if (month < 1 || month > 12 || day < 1 || day > daysInMonth) return null;
    }
  }
  const parsed = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function startOfUtcDay(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function subtractUtcMonths(date, months) {
  const targetMonth = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - months, 1));
  const finalDay = new Date(Date.UTC(targetMonth.getUTCFullYear(), targetMonth.getUTCMonth() + 1, 0)).getUTCDate();
  targetMonth.setUTCDate(Math.min(date.getUTCDate(), finalDay));
  return targetMonth;
}

export function createEvidenceWindow(preset, { generatedAt, asOf } = {}) {
  const key = normalizeEvidenceWindowPreset(preset);
  const referenceSource = asOf !== undefined && asOf !== null && asOf !== "" ? "asOf" : "generatedAt";
  const referenceValue = referenceSource === "asOf" ? asOf : generatedAt;
  const parsedReference = parseDate(referenceValue);
  if (!parsedReference) {
    throw new RangeError(`A valid ${referenceSource} date is required to calculate an evidence window`);
  }

  const referenceDate = startOfUtcDay(parsedReference);
  const definition = EVIDENCE_WINDOW_PRESETS[key];
  let cutoffDate = null;
  if (definition.days) {
    cutoffDate = new Date(referenceDate.getTime() - definition.days * 86400000);
  } else if (definition.months) {
    cutoffDate = subtractUtcMonths(referenceDate, definition.months);
  }

  return Object.freeze({
    preset: key,
    label: definition.label,
    referenceSource,
    asOf: referenceDate.toISOString(),
    cutoff: cutoffDate?.toISOString() || null,
    granularity: "utc-day",
  });
}

function partitionDatedEvidence(entries, dateField, preset, options) {
  if (!Array.isArray(entries)) throw new TypeError("Evidence entries must be an array");
  const window = createEvidenceWindow(preset, options);
  const asOfTime = new Date(window.asOf).getTime();
  const cutoffTime = window.cutoff ? new Date(window.cutoff).getTime() : null;

  const all = entries.map((entry) => {
    const rawDate = entry?.[dateField];
    const parsed = parseDate(rawDate);
    let status;
    let evidenceDate = null;

    if (rawDate === null || rawDate === undefined || rawDate === "") {
      status = "undated";
    } else if (!parsed) {
      status = "invalid-date";
    } else {
      const date = startOfUtcDay(parsed);
      const time = date.getTime();
      evidenceDate = date.toISOString();
      if (time > asOfTime) status = "future";
      else if (cutoffTime === null || time >= cutoffTime) status = "in-window";
      else status = "out-of-window";
    }

    return {
      ...entry,
      evidenceWindow: Object.freeze({ field: dateField, date: evidenceDate, status }),
    };
  });

  const withStatus = (status) => all.filter((entry) => entry.evidenceWindow.status === status);
  const inWindow = withStatus("in-window");
  const outOfWindow = withStatus("out-of-window");
  const undated = withStatus("undated");
  const invalid = withStatus("invalid-date");
  const future = withStatus("future");

  return {
    window,
    all,
    inWindow,
    outOfWindow,
    undated,
    invalid,
    future,
    excluded: [...outOfWindow, ...undated, ...invalid, ...future],
  };
}

export function classifyCampaignsByWindow(campaigns, preset, options = {}) {
  return partitionDatedEvidence(campaigns, "lastSeen", preset, options);
}

export function classifyKevsByWindow(vulnerabilities, preset, options = {}) {
  return partitionDatedEvidence(vulnerabilities, "dateAdded", preset, options);
}

export function classifySignalsByWindow(signals, preset, options = {}) {
  return partitionDatedEvidence(signals, "publishedAt", preset, options);
}

export function normalizeTopFocus(value, fallback = 10) {
  const candidate = typeof value === "string"
    ? Number(normaliseString(value).replace(/^top\s+/, ""))
    : Number(value);
  if (TOP_FOCUS_VALUES.includes(candidate)) return candidate;

  const fallbackCandidate = typeof fallback === "string"
    ? Number(normaliseString(fallback).replace(/^top\s+/, ""))
    : Number(fallback);
  return TOP_FOCUS_VALUES.includes(fallbackCandidate) ? fallbackCandidate : 10;
}

export function selectTopFocus(entries, value, fallback = 10) {
  if (!Array.isArray(entries)) throw new TypeError("Focus entries must be an array");
  const requestedCount = normalizeTopFocus(value, fallback);
  if (!entries.length) {
    return {
      requestedCount,
      actualCount: 0,
      cutoffRank: null,
      includedCutoffTies: false,
      focused: [],
      remaining: [],
    };
  }

  const boundaryIndex = Math.min(requestedCount, entries.length) - 1;
  const boundary = entries[boundaryIndex];
  const rankedCutoff = Number(boundary?.competitionRank ?? boundary?.rank);
  const cutoffRank = Number.isFinite(rankedCutoff) ? rankedCutoff : boundaryIndex + 1;
  let endIndex = boundaryIndex + 1;

  while (endIndex < entries.length) {
    const nextRank = Number(entries[endIndex]?.competitionRank ?? entries[endIndex]?.rank);
    if (!Number.isFinite(nextRank) || nextRank !== cutoffRank) break;
    endIndex += 1;
  }

  const focused = entries.slice(0, endIndex);
  return {
    requestedCount,
    actualCount: focused.length,
    cutoffRank,
    includedCutoffTies: focused.length > requestedCount,
    focused,
    remaining: entries.slice(endIndex),
  };
}

function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}

function round1(value) {
  return Math.round(value * 10) / 10;
}

function unique(values) {
  return [...new Set((values || []).filter(Boolean))];
}

export function specificity(breadth, universeSize) {
  if (breadth <= 0 || universeSize <= 1) return 0;
  return clamp(Math.log2(universeSize / breadth) / Math.log2(universeSize), 0, 1);
}

function fitBand(profileFit) {
  if (profileFit >= 70) return "Focused match";
  if (profileFit >= 40) return "Material match";
  return "Broad match";
}

function universes(actors, supplied = {}) {
  return {
    sectors: supplied.sectors?.length
      ? supplied.sectors.length
      : unique(actors.flatMap((actor) => actor.sectors || [])).length,
    countries: supplied.countries?.length
      ? supplied.countries.length
      : unique(actors.flatMap((actor) => actor.countries || [])).length,
  };
}

export function scoreActors(actors, sector, country, suppliedUniverses = {}) {
  const universe = universes(actors, suppliedUniverses);
  const ranked = actors
    .map((actor) => {
      const sectorMatch = actor.sectors?.includes(sector) || false;
      const countryMatch = actor.countries?.includes(country) || false;
      if (!sectorMatch && !countryMatch) return null;

      const sectorSpecificity = sectorMatch
        ? specificity(actor.sectors.length, universe.sectors)
        : 0;
      const countrySpecificity = countryMatch
        ? specificity(actor.countries.length, universe.countries)
        : 0;
      const sectorPoints = 50 * sectorSpecificity;
      const countryPoints = 50 * countrySpecificity;
      const profileFitExact = sectorPoints + countryPoints;
      const matchDimensions = [sectorMatch ? "sector" : null, countryMatch ? "country" : null].filter(Boolean);

      return {
        ...actor,
        profileFitExact,
        profileFit: round1(profileFitExact),
        fitBand: fitBand(profileFitExact),
        analyticConfidence: actor.targetingEvidence ? "Low" : "Unknown",
        sectorMatch,
        countryMatch,
        matchDimensions,
        jointTargetingEvidence: false,
        namedOrganisationTargetingEvidence: false,
        assessmentType: "profile_relevance_inference",
        scoreComponents: {
          sector: {
            matched: sectorMatch,
            actorBreadth: actor.sectors?.length || 0,
            universe: universe.sectors,
            specificity: round1(sectorSpecificity * 100),
            points: round1(sectorPoints),
          },
          country: {
            matched: countryMatch,
            actorBreadth: actor.countries?.length || 0,
            universe: universe.countries,
            specificity: round1(countrySpecificity * 100),
            points: round1(countryPoints),
          },
        },
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.profileFitExact - a.profileFitExact || a.id.localeCompare(b.id));

  let previousFit = null;
  let previousRank = 0;
  return ranked.map((actor, index) => {
    const equal = previousFit !== null && Math.abs(actor.profileFitExact - previousFit) < 1e-9;
    const competitionRank = equal ? previousRank : index + 1;
    previousFit = actor.profileFitExact;
    previousRank = competitionRank;
    return { ...actor, competitionRank };
  });
}

function aggregateRelationships(rankedActors, catalogue) {
  const catalogueById = new Map(catalogue.map((entry) => [entry.id, entry]));
  const mappedActors = rankedActors.filter((actor) => actor.techniques?.length);
  const totalFitMass = rankedActors.reduce((sum, actor) => sum + actor.profileFitExact / 100, 0);
  const mappedFitMass = mappedActors.reduce((sum, actor) => sum + actor.profileFitExact / 100, 0);
  const weightedDenominator = mappedFitMass || 1;
  const adjustedDenominator = mappedActors.reduce((sum, actor) => {
    const weight = actor.profileFitExact / 100;
    return sum + weight / Math.sqrt(Math.max(1, actor.techniques.length));
  }, 0) || 1;

  return { catalogueById, mappedActors, totalFitMass, mappedFitMass, weightedDenominator, adjustedDenominator };
}

export function aggregateTechniques(rankedActors, techniques) {
  const context = aggregateRelationships(rankedActors, techniques);
  const aggregate = new Map();

  for (const actor of context.mappedActors) {
    const actorWeight = actor.profileFitExact / 100;
    const adjustedWeight = actorWeight / Math.sqrt(Math.max(1, actor.techniques.length));
    for (const techniqueId of actor.techniques || []) {
      const current = aggregate.get(techniqueId) || {
        id: techniqueId,
        actorIds: new Set(),
        focusedActorIds: new Set(),
        weightedNumerator: 0,
        adjustedNumerator: 0,
      };
      current.actorIds.add(actor.id);
      if (actor.fitBand === "Focused match") current.focusedActorIds.add(actor.id);
      current.weightedNumerator += actorWeight;
      current.adjustedNumerator += adjustedWeight;
      aggregate.set(techniqueId, current);
    }
  }

  const mappingCompleteness = context.totalFitMass
    ? round1((context.mappedFitMass / context.totalFitMass) * 100)
    : 0;

  return [...aggregate.values()]
    .map((entry) => {
      const technique = context.catalogueById.get(entry.id) || { id: entry.id };
      const weightedCoverage = entry.weightedNumerator / context.weightedDenominator;
      const adjustedCoverage = entry.adjustedNumerator / context.adjustedDenominator;
      const techniqueScore = round1(100 * Math.min(weightedCoverage, adjustedCoverage));
      return {
        ...technique,
        actorCount: entry.actorIds.size,
        focusedActorCount: entry.focusedActorIds.size,
        actorIds: [...entry.actorIds],
        weightedCoverage: round1(weightedCoverage * 100),
        documentationAdjustedCoverage: round1(adjustedCoverage * 100),
        techniqueScore,
        weight: techniqueScore,
        mappingCompleteness,
        operational: (technique.tactics || []).some((tactic) => OPERATIONAL_TACTICS.has(tactic)),
      };
    })
    .sort((a, b) => b.techniqueScore - a.techniqueScore || b.actorCount - a.actorCount || a.id.localeCompare(b.id));
}

export function aggregateSoftware(rankedActors, software) {
  const softwareById = new Map(software.map((entry) => [entry.id, entry]));
  const aggregate = new Map();
  const denominator = rankedActors.reduce((sum, actor) => sum + actor.profileFitExact / 100, 0) || 1;

  for (const actor of rankedActors) {
    const actorWeight = actor.profileFitExact / 100;
    const breadthAdjustment = actorWeight / Math.sqrt(Math.max(1, actor.software?.length || 1));
    for (const softwareId of actor.software || []) {
      const current = aggregate.get(softwareId) || { id: softwareId, actorIds: new Set(), weight: 0, adjusted: 0 };
      current.actorIds.add(actor.id);
      current.weight += actorWeight;
      current.adjusted += breadthAdjustment;
      aggregate.set(softwareId, current);
    }
  }

  return [...aggregate.values()]
    .map((entry) => ({
      ...softwareById.get(entry.id),
      id: entry.id,
      actorCount: entry.actorIds.size,
      actorIds: [...entry.actorIds],
      softwareScore: round1((entry.weight / denominator) * 100),
      documentationAdjustedWeight: round1(entry.adjusted * 100),
    }))
    .sort((a, b) => b.softwareScore - a.softwareScore || b.actorCount - a.actorCount || a.id.localeCompare(b.id));
}

export function relevantCampaigns(campaigns, rankedActors, asOf = new Date()) {
  const actorFit = new Map(rankedActors.map((actor) => [actor.id, actor.profileFitExact]));
  const now = new Date(asOf).getTime();

  return campaigns
    .map((campaign) => {
      const linkedFits = (campaign.actorIds || [])
        .map((actorId) => actorFit.get(actorId))
        .filter((score) => Number.isFinite(score));
      if (!linkedFits.length) return null;

      const lastSeenTime = campaign.lastSeen ? new Date(campaign.lastSeen).getTime() : Number.NaN;
      const validLastSeen = Number.isFinite(lastSeenTime) && lastSeenTime <= now;
      const ageDays = validLastSeen ? Math.max(0, (now - lastSeenTime) / 86400000) : null;
      const recencyScore = ageDays === null ? null : round1(100 * 2 ** (-ageDays / 730));
      const campaignProfileFit = Math.max(...linkedFits);

      return {
        ...campaign,
        campaignProfileFit: round1(campaignProfileFit),
        relevanceScore: round1(campaignProfileFit),
        recencyScore,
        ageDays: ageDays === null ? null : Math.round(ageDays),
        campaignSignal: recencyScore === null ? null : round1((campaignProfileFit / 100) * recencyScore),
      };
    })
    .filter(Boolean)
    .sort((a, b) =>
      b.campaignProfileFit - a.campaignProfileFit ||
      (b.recencyScore ?? -1) - (a.recencyScore ?? -1) ||
      a.id.localeCompare(b.id));
}

export function filterVulnerabilities(vulnerabilities, technology) {
  const terms = String(technology || "")
    .split(",")
    .map((term) => term.trim().toLowerCase())
    .filter(Boolean);

  return vulnerabilities
    .map((entry) => {
      const haystack = `${entry.vendor} ${entry.product} ${entry.name} ${entry.cve}`.toLowerCase();
      const matchedTerms = terms.filter((term) => haystack.includes(term));
      if (terms.length && !matchedTerms.length) return null;
      return {
        ...entry,
        environmentMatch: terms.length ? "possible" : "unknown",
        exposureConfirmed: false,
        matchMethod: terms.length ? "keyword_filter" : "none",
        matchedTerms,
      };
    })
    .filter(Boolean)
    .sort((a, b) => {
      const ransomware = Number(String(b.ransomware).toLowerCase() === "known") -
        Number(String(a.ransomware).toLowerCase() === "known");
      return ransomware || String(b.dateAdded).localeCompare(String(a.dateAdded)) || a.cve.localeCompare(b.cve);
    });
}

export function attackTechniqueUrl(id) {
  if (!id) return "https://attack.mitre.org/";
  const [technique, subTechnique] = id.split(".");
  return subTechnique
    ? `https://attack.mitre.org/techniques/${technique}/${subTechnique}/`
    : `https://attack.mitre.org/techniques/${technique}/`;
}

export function navigatorLayer(profileName, techniques, attackVersion, scope = {}) {
  const versions = { navigator: "5.2.0", layer: "4.5" };
  if (attackVersion) versions.attack = String(attackVersion);
  return {
    name: profileName,
    versions,
    domain: "enterprise-attack",
    description: `ATT&CK techniques ranked by documentation-adjusted profile coverage${scope.focus ? ` for ${scope.focus}` : ""}. This is relevance, not likelihood or detection efficacy. ATT&CK actor-technique relationships are undated${scope.evidenceWindow ? `; the ${scope.evidenceWindow} dated-evidence window applies only to supporting campaign, signal and KEV context` : ""}.`,
    techniques: techniques.map((technique) => ({
      techniqueID: technique.id,
      score: Math.max(1, Math.round(technique.techniqueScore || 0)),
      comment: `${technique.actorCount} profile-matched actor${technique.actorCount === 1 ? "" : "s"}; ${technique.documentationAdjustedCoverage}% documentation-adjusted coverage`,
      enabled: true,
      showSubtechniques: true,
    })),
    gradient: {
      colors: ["#dce7ed", "#e7b85c", "#e85d5d"],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [],
    metadata: [
      { name: "Method", value: "Profile fit with documentation-breadth adjustment" },
      ...(scope.focus ? [{ name: "Analysis focus", value: scope.focus }] : []),
      ...(scope.evidenceWindow ? [{ name: "Dated evidence window", value: scope.evidenceWindow }] : []),
      { name: "Date boundary", value: "ATT&CK actor-technique relationships are undated historical context" },
    ],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}
