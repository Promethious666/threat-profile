const ATTACK_SOURCE = "MITRE ATT&CK";

function externalId(object) {
  return object.external_references?.find((reference) => reference.external_id)?.external_id || null;
}

function sortedUnique(values) {
  return [...new Set((values || []).filter(Boolean))].sort((a, b) => String(a).localeCompare(String(b)));
}

function markdownUrls(value) {
  const urls = [];
  for (const match of String(value || "").matchAll(/https:\/\/[^\s)\]<>]+/g)) {
    urls.push(match[0].replace(/[.,;]+$/, ""));
  }
  return sortedUnique(urls);
}

function externalUrls(object) {
  return sortedUnique([
    ...(object.external_references || []).map((reference) => reference.url),
    ...markdownUrls(object.description),
  ].filter((url) => typeof url === "string" && /^https:\/\//.test(url)));
}

function activeObject(object) {
  return !object.revoked && !object.x_mitre_deprecated;
}

function summary(value, maxLength = 600) {
  if (!value) return "";
  const clean = String(value)
    .replace(/<[^>]+>/g, " ")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
  return clean.length > maxLength ? `${clean.slice(0, maxLength - 1).trimEnd()}…` : clean;
}

function arrayValue(value) {
  if (Array.isArray(value)) return value;
  return value ? [value] : [];
}

function recordCount(key, value) {
  if (key === "attack") return value?.actors?.length || 0;
  if (key === "targeting") return value?.targets?.length || 0;
  if (key === "kev") return value?.vulnerabilities?.length || 0;
  return 0;
}

function duplicateValues(values) {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates];
}

export function normaliseAttack(bundle, generatedAt = new Date().toISOString()) {
  const objects = Array.isArray(bundle?.objects) ? bundle.objects.filter(activeObject) : [];
  const actorByStix = new Map();
  const techniqueByStix = new Map();
  const softwareByStix = new Map();
  const campaignByStix = new Map();

  for (const object of objects) {
    const id = externalId(object);
    if (!id) continue;

    if (object.type === "intrusion-set") {
      actorByStix.set(object.id, {
        id,
        name: object.name,
        aliases: sortedUnique(object.aliases || []),
        description: summary(object.description),
        created: object.created || null,
        modified: object.modified || null,
        references: externalUrls(object),
        techniques: new Set(),
        software: new Set(),
        campaigns: new Set(),
        procedures: [],
      });
    }

    if (object.type === "attack-pattern") {
      techniqueByStix.set(object.id, {
        id,
        name: object.name,
        description: summary(object.description),
        platforms: sortedUnique(object.x_mitre_platforms || []),
        tactics: sortedUnique((object.kill_chain_phases || []).map((phase) => phase.phase_name)),
        dataSources: sortedUnique(object.x_mitre_data_sources || []),
        created: object.created || null,
        modified: object.modified || null,
        references: externalUrls(object),
      });
    }

    if (object.type === "malware" || object.type === "tool") {
      softwareByStix.set(object.id, {
        id,
        name: object.name,
        kind: object.type,
        description: summary(object.description),
        platforms: sortedUnique(object.x_mitre_platforms || []),
        created: object.created || null,
        modified: object.modified || null,
        references: externalUrls(object),
      });
    }

    if (object.type === "campaign") {
      campaignByStix.set(object.id, {
        id,
        name: object.name,
        description: summary(object.description),
        firstSeen: object.first_seen || null,
        lastSeen: object.last_seen || null,
        created: object.created || null,
        modified: object.modified || null,
        references: externalUrls(object),
        actorIds: new Set(),
        techniques: new Set(),
        software: new Set(),
      });
    }
  }

  for (const relationship of objects.filter((object) => object.type === "relationship")) {
    const sourceActor = actorByStix.get(relationship.source_ref);
    const targetActor = actorByStix.get(relationship.target_ref);
    const sourceCampaign = campaignByStix.get(relationship.source_ref);
    const targetCampaign = campaignByStix.get(relationship.target_ref);
    const targetTechnique = techniqueByStix.get(relationship.target_ref);
    const targetSoftware = softwareByStix.get(relationship.target_ref);

    if (relationship.relationship_type === "uses") {
      if (sourceActor && targetTechnique) {
        sourceActor.techniques.add(targetTechnique.id);
        sourceActor.procedures.push({
          techniqueId: targetTechnique.id,
          description: summary(relationship.description, 360),
          references: externalUrls(relationship),
        });
      }
      if (sourceActor && targetSoftware) sourceActor.software.add(targetSoftware.id);
      if (sourceCampaign && targetTechnique) sourceCampaign.techniques.add(targetTechnique.id);
      if (sourceCampaign && targetSoftware) sourceCampaign.software.add(targetSoftware.id);
    }

    if (relationship.relationship_type === "attributed-to") {
      if (sourceCampaign && targetActor) {
        sourceCampaign.actorIds.add(targetActor.id);
        targetActor.campaigns.add(sourceCampaign.id);
      }
      if (sourceActor && targetCampaign) {
        targetCampaign.actorIds.add(sourceActor.id);
        sourceActor.campaigns.add(targetCampaign.id);
      }
    }
  }

  const actors = [...actorByStix.values()]
    .map((actor) => ({
      ...actor,
      techniques: sortedUnique([...actor.techniques]),
      software: sortedUnique([...actor.software]),
      campaigns: sortedUnique([...actor.campaigns]),
      procedures: actor.procedures
        .filter((procedure) => procedure.description || procedure.references.length)
        .sort((a, b) => a.techniqueId.localeCompare(b.techniqueId)),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const campaigns = [...campaignByStix.values()]
    .map((campaign) => ({
      ...campaign,
      actorIds: sortedUnique([...campaign.actorIds]),
      techniques: sortedUnique([...campaign.techniques]),
      software: sortedUnique([...campaign.software]),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const collection = objects.find((object) => object.type === "x-mitre-collection");
  const version = collection?.x_mitre_version ||
    collection?.x_mitre_attack_spec_version ||
    bundle?.x_mitre_attack_spec_version ||
    bundle?.spec_version ||
    null;

  return {
    generatedAt,
    source: ATTACK_SOURCE,
    sourceUrl: "https://github.com/mitre-attack/attack-stix-data",
    version,
    actors,
    techniques: [...techniqueByStix.values()].sort((a, b) => a.id.localeCompare(b.id)),
    software: [...softwareByStix.values()].sort((a, b) => a.id.localeCompare(b.id)),
    campaigns,
  };
}

export function normaliseTargeting(galaxy, generatedAt = new Date().toISOString()) {
  const grouped = new Map();

  for (const entry of galaxy?.values || []) {
    const id = entry.meta?.group_attack_id;
    if (!id) continue;
    const current = grouped.get(id) || {
      id,
      name: entry.value,
      descriptions: [],
      sectors: [],
      countries: [],
      originCountries: [],
      motivations: [],
      sourceNames: [],
      owners: [],
      references: [],
      tags: [],
      recordIds: [],
    };

    current.descriptions.push(summary(entry.description));
    current.sectors.push(...arrayValue(entry.meta?.target_categories));
    current.countries.push(...arrayValue(entry.meta?.observed_countries));
    current.originCountries.push(...arrayValue(entry.meta?.country));
    current.motivations.push(...arrayValue(entry.meta?.observed_motivations));
    current.sourceNames.push(...arrayValue(entry.meta?.source));
    current.owners.push(...arrayValue(entry.meta?.owner));
    current.references.push(...markdownUrls(entry.description), ...arrayValue(entry.meta?.refs));
    current.tags.push(...arrayValue(entry.meta?.tags));
    current.recordIds.push(entry.uuid);
    grouped.set(id, current);
  }

  const targets = [...grouped.values()]
    .map((entry) => ({
      id: entry.id,
      name: entry.name,
      description: sortedUnique(entry.descriptions).join(" "),
      sectors: sortedUnique(entry.sectors),
      countries: sortedUnique(entry.countries),
      originCountries: sortedUnique(entry.originCountries),
      motivations: sortedUnique(entry.motivations),
      sourceNames: sortedUnique(entry.sourceNames),
      owners: sortedUnique(entry.owners),
      references: sortedUnique(entry.references.filter((url) => /^https:\/\//.test(url))),
      tags: sortedUnique(entry.tags),
      recordIds: sortedUnique(entry.recordIds),
      observedAt: null,
      evidenceType: "aggregated historical targeting context",
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    generatedAt,
    source: "MISP Galaxy Tidal Groups",
    sourceUrl: "https://github.com/MISP/misp-galaxy/blob/main/clusters/tidal-groups.json",
    targets,
  };
}

export function normaliseKev(catalog, generatedAt = new Date().toISOString()) {
  const vulnerabilities = (catalog?.vulnerabilities || [])
    .map((entry) => ({
      cve: entry.cveID,
      vendor: entry.vendorProject,
      product: entry.product,
      name: entry.vulnerabilityName,
      description: summary(entry.shortDescription),
      dateAdded: entry.dateAdded,
      dueDate: entry.dueDate,
      ransomware: entry.knownRansomwareCampaignUse || "Unknown",
      action: entry.requiredAction || "",
      notes: entry.notes || "",
      references: markdownUrls(entry.notes),
      cwes: sortedUnique(entry.cwes || []),
    }))
    .filter((entry) => entry.cve)
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));

  return {
    generatedAt,
    source: "CISA Known Exploited Vulnerabilities",
    sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    catalogVersion: catalog?.catalogVersion || null,
    dateReleased: catalog?.dateReleased || null,
    vulnerabilities,
  };
}

export function combineSources(attack, targeting, kev, health, generatedAt = new Date().toISOString()) {
  const targetingById = new Map(targeting.targets.map((entry) => [entry.id, entry]));
  const attackIds = new Set(attack.actors.map((actor) => actor.id));
  const actors = attack.actors.map((actor) => {
    const target = targetingById.get(actor.id);
    return {
      ...actor,
      sectors: target?.sectors || [],
      countries: target?.countries || [],
      originCountries: target?.originCountries || [],
      motivations: target?.motivations || [],
      targetingEvidence: target ? {
        description: target.description,
        evidenceType: target.evidenceType,
        observedAt: target.observedAt,
        owners: target.owners,
        recordIds: target.recordIds,
        references: target.references,
        sourceNames: target.sourceNames,
      } : null,
      targetingSource: target ? targeting.source : null,
    };
  });

  const sectors = sortedUnique(actors.flatMap((actor) => actor.sectors));
  const countries = sortedUnique(actors.flatMap((actor) => actor.countries));
  const unmatchedTargetingIds = targeting.targets.map((target) => target.id).filter((id) => !attackIds.has(id));

  return {
    schemaVersion: 2,
    generatedAt,
    health,
    versions: { attack: attack.version, kev: kev.catalogVersion },
    coverage: {
      actorsTotal: actors.length,
      actorsWithTargeting: actors.filter((actor) => actor.targetingEvidence).length,
      actorsWithProfileData: actors.filter((actor) => actor.sectors.length || actor.countries.length).length,
      targetingRecords: targeting.targets.length,
      unmatchedTargetingIds,
    },
    sectors,
    countries,
    actors,
    techniques: attack.techniques,
    software: attack.software,
    campaigns: attack.campaigns,
    vulnerabilities: kev.vulnerabilities,
  };
}

export function validateNormalisedSource(key, value) {
  const errors = [];
  const minimums = { attack: 100, targeting: 150, kev: 500 };
  const count = recordCount(key, value);
  if (!value || typeof value !== "object") errors.push(`${key} is not an object`);
  if (count < minimums[key]) errors.push(`${key} record count ${count} is below ${minimums[key]}`);

  if (key === "attack") {
    if ((value?.techniques?.length || 0) < 500) errors.push("ATT&CK technique coverage is below 500");
    if ((value?.campaigns?.length || 0) < 20) errors.push("ATT&CK campaign coverage is below 20");
    const duplicateIds = duplicateValues((value?.actors || []).map((entry) => entry.id));
    if (duplicateIds.length) errors.push(`ATT&CK contains duplicate actor IDs: ${duplicateIds.slice(0, 5).join(", ")}`);
  }

  if (key === "targeting") {
    const duplicateIds = duplicateValues((value?.targets || []).map((entry) => entry.id));
    if (duplicateIds.length) errors.push(`Targeting contains duplicate group IDs: ${duplicateIds.slice(0, 5).join(", ")}`);
  }

  if (key === "kev") {
    const duplicateIds = duplicateValues((value?.vulnerabilities || []).map((entry) => entry.cve));
    if (duplicateIds.length) errors.push(`KEV contains duplicate CVEs: ${duplicateIds.slice(0, 5).join(", ")}`);
  }
  return errors;
}

export function validateCombinedData(value) {
  const errors = [];
  if (!value || typeof value !== "object") return ["combined intelligence is not an object"];
  if (value.schemaVersion !== 2) errors.push("combined intelligence schemaVersion must be 2");
  if ((value.actors?.length || 0) < 100) errors.push("combined actor coverage is below 100");
  if ((value.techniques?.length || 0) < 500) errors.push("combined technique coverage is below 500");
  if ((value.vulnerabilities?.length || 0) < 500) errors.push("combined KEV coverage is below 500");
  if ((value.sectors?.length || 0) < 10) errors.push("combined sector coverage is below 10");
  if ((value.countries?.length || 0) < 20) errors.push("combined country coverage is below 20");
  if ((value.health?.length || 0) !== 3) errors.push("combined source health must contain three sources");
  if ((value.coverage?.actorsWithProfileData || 0) < 50) errors.push("fewer than 50 actors have usable profile context");
  return errors;
}

export function assertValidNormalisedSource(key, value) {
  const errors = validateNormalisedSource(key, value);
  if (errors.length) throw new Error(errors.join("; "));
}

export function assertValidCombinedData(value) {
  const errors = validateCombinedData(value);
  if (errors.length) throw new Error(errors.join("; "));
}

export function sourceRecordCount(key, value) {
  return recordCount(key, value);
}
