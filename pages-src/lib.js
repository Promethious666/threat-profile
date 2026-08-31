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

export function navigatorLayer(profileName, techniques, attackVersion) {
  const versions = { navigator: "5.2.0", layer: "4.5" };
  if (attackVersion) versions.attack = String(attackVersion);
  return {
    name: profileName,
    versions,
    domain: "enterprise-attack",
    description: "ATT&CK techniques ranked by documentation-adjusted profile coverage. This is relevance, not likelihood or detection priority.",
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
    metadata: [{ name: "Method", value: "Profile fit with documentation-breadth adjustment" }],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}
