import test from "node:test";
import assert from "node:assert/strict";
import {
  combineSources,
  normaliseAttack,
  normaliseKev,
  normaliseTargeting,
  validateCombinedData,
  validateNormalisedSource,
} from "../scripts/intelligence-lib.mjs";

test("normaliseAttack retains actor, relationship, technique, and campaign provenance", () => {
  const bundle = {
    objects: [
      {
        type: "intrusion-set", id: "intrusion-set--1", name: "Group", created: "2024-01-01T00:00:00Z", modified: "2025-01-01T00:00:00Z",
        description: "Actor description. [Source](https://example.org/actor)", aliases: ["Alias"],
        external_references: [{ external_id: "G0001", url: "https://attack.mitre.org/groups/G0001/" }],
      },
      {
        type: "attack-pattern", id: "attack-pattern--1", name: "Technique", x_mitre_platforms: ["Windows"],
        kill_chain_phases: [{ phase_name: "execution" }], x_mitre_data_sources: ["Process: Process Creation"],
        external_references: [{ external_id: "T1000", url: "https://attack.mitre.org/techniques/T1000/" }],
      },
      {
        type: "campaign", id: "campaign--1", name: "Campaign", first_seen: "2025-01-01T00:00:00Z", last_seen: "2025-02-01T00:00:00Z",
        external_references: [{ external_id: "C0001", url: "https://attack.mitre.org/campaigns/C0001/" }],
      },
      {
        type: "relationship", id: "relationship--1", relationship_type: "uses", source_ref: "intrusion-set--1", target_ref: "attack-pattern--1",
        description: "Observed use. [Report](https://example.org/report)",
      },
      { type: "relationship", id: "relationship--2", relationship_type: "attributed-to", source_ref: "campaign--1", target_ref: "intrusion-set--1" },
    ],
  };

  const result = normaliseAttack(bundle, "2026-01-01T00:00:00Z");
  assert.deepEqual(result.actors[0].techniques, ["T1000"]);
  assert.deepEqual(result.actors[0].campaigns, ["C0001"]);
  assert.deepEqual(result.campaigns[0].actorIds, ["G0001"]);
  assert.equal(result.techniques[0].platforms[0], "Windows");
  assert.match(result.actors[0].procedures[0].description, /Observed use/);
  assert.deepEqual(result.actors[0].procedures[0].references, ["https://example.org/report"]);
  assert.deepEqual(result.actors[0].references, [
    "https://attack.mitre.org/groups/G0001/",
    "https://example.org/actor",
  ]);
});

test("targeting normalisation preserves source evidence without inventing observation dates", () => {
  const targeting = normaliseTargeting({ values: [{
    uuid: "record-1",
    value: "Group",
    description: "Historical context [Report](https://example.org/targeting)",
    meta: {
      group_attack_id: "G0001",
      target_categories: ["Financial Services"],
      observed_countries: ["GB"],
      country: ["RU"],
      observed_motivations: ["Espionage"],
      source: ["Tidal"],
      owner: ["MISP"],
      refs: ["https://example.org/reference"],
      tags: ["type:actor"],
    },
  }] }, "2026-01-01T00:00:00Z");

  const target = targeting.targets[0];
  assert.equal(target.id, "G0001");
  assert.deepEqual(target.sectors, ["Financial Services"]);
  assert.deepEqual(target.countries, ["GB"]);
  assert.deepEqual(target.originCountries, ["RU"]);
  assert.equal(target.observedAt, null);
  assert.equal(target.evidenceType, "aggregated historical targeting context");
  assert.deepEqual(target.recordIds, ["record-1"]);
  assert.deepEqual(target.references, ["https://example.org/reference", "https://example.org/targeting"]);
});

test("KEV normalisation preserves operational context and references", () => {
  const kev = normaliseKev({
    catalogVersion: "test",
    vulnerabilities: [{
      cveID: "CVE-2026-0001", vendorProject: "Vendor", product: "Product", vulnerabilityName: "Vulnerability",
      shortDescription: "Description", dateAdded: "2026-01-01", dueDate: "2026-01-22",
      knownRansomwareCampaignUse: "Known", requiredAction: "Patch", notes: "See https://example.org/advisory.", cwes: ["CWE-79"],
    }],
  }, "2026-01-01T00:00:00Z");
  const item = kev.vulnerabilities[0];
  assert.equal(item.cve, "CVE-2026-0001");
  assert.equal(item.action, "Patch");
  assert.deepEqual(item.cwes, ["CWE-79"]);
  assert.deepEqual(item.references, ["https://example.org/advisory"]);
});

test("combineSources joins targeting evidence and publishes schema version 2", () => {
  const attack = {
    version: "17",
    actors: [{ id: "G0001", name: "Group", aliases: [], references: [], techniques: [], software: [], campaigns: [], procedures: [] }],
    techniques: [], software: [], campaigns: [],
  };
  const targeting = {
    source: "Targeting",
    targets: [{
      id: "G0001", description: "Evidence", sectors: ["Financial Services"], countries: ["GB"], originCountries: ["RU"], motivations: ["Espionage"],
      evidenceType: "aggregated historical targeting context", observedAt: null, owners: ["Owner"], recordIds: ["record-1"], references: ["https://example.org"], sourceNames: ["Source"],
    }],
  };
  const kev = { catalogVersion: "2026.01", vulnerabilities: [] };
  const combined = combineSources(attack, targeting, kev, [{ key: "attack" }, { key: "targeting" }, { key: "kev" }], "2026-01-01T00:00:00Z");

  assert.equal(combined.schemaVersion, 2);
  assert.deepEqual(combined.sectors, ["Financial Services"]);
  assert.deepEqual(combined.countries, ["GB"]);
  assert.equal(combined.actors[0].targetingSource, "Targeting");
  assert.equal(combined.actors[0].targetingEvidence.observedAt, null);
  assert.equal(combined.coverage.actorsWithTargeting, 1);
});

test("validators reject undersized or legacy-shaped intelligence", () => {
  assert.ok(validateNormalisedSource("attack", { actors: [], techniques: [], campaigns: [] }).length >= 3);
  assert.ok(validateCombinedData({ schemaVersion: 1 }).some((error) => error.includes("schemaVersion")));
});
