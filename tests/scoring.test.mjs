import test from "node:test";
import assert from "node:assert/strict";
import {
  aggregateTechniques,
  filterVulnerabilities,
  navigatorLayer,
  relevantCampaigns,
  scoreActors,
  specificity,
} from "../pages-src/lib.js";

const universes = {
  sectors: ["A", "B", "C", "D"],
  countries: ["GB", "US", "DE", "FR", "NL", "ES", "IT", "CA"],
};

function actor(overrides = {}) {
  return {
    id: "G0001",
    name: "Example actor",
    sectors: ["A"],
    countries: ["GB"],
    techniques: [],
    software: [],
    targetingEvidence: { evidenceType: "aggregated historical targeting context" },
    ...overrides,
  };
}

test("specificity gives narrow attributes more weight than broad ones", () => {
  assert.equal(specificity(1, 4), 1);
  assert.equal(specificity(4, 4), 0);
  assert.ok(specificity(2, 8) > specificity(4, 8));
});

test("an exact single-sector and single-country match scores 100", () => {
  const [result] = scoreActors([actor()], "A", "GB", universes);
  assert.equal(result.profileFit, 100);
  assert.equal(result.fitBand, "Focused match");
  assert.equal(result.assessmentType, "profile_relevance_inference");
  assert.equal(result.jointTargetingEvidence, false);
});

test("a source record spanning the entire universe remains visible but scores zero", () => {
  const broad = actor({ sectors: universes.sectors, countries: universes.countries });
  const [result] = scoreActors([broad], "A", "GB", universes);
  assert.equal(result.profileFit, 0);
  assert.equal(result.fitBand, "Broad match");
});

test("profile fit follows the documented logarithmic breadth adjustment", () => {
  const candidate = actor({ sectors: ["A", "B"], countries: ["GB", "US"] });
  const [result] = scoreActors([candidate], "A", "GB", universes);
  assert.equal(result.profileFit, 58.3);
  assert.equal(result.scoreComponents.sector.points, 25);
  assert.equal(result.scoreComponents.country.points, 33.3);
});

test("ties use competition ranks and remain stable across input order", () => {
  const candidates = [
    actor({ id: "G0002", name: "Beta" }),
    actor({ id: "G0001", name: "Alpha" }),
    actor({ id: "G0003", name: "Gamma", sectors: ["A", "B"], countries: ["GB", "US"] }),
  ];
  const first = scoreActors(candidates, "A", "GB", universes);
  const second = scoreActors([...candidates].reverse(), "A", "GB", universes);
  assert.deepEqual(first.map(({ id, competitionRank }) => [id, competitionRank]), [
    ["G0001", 1], ["G0002", 1], ["G0003", 3],
  ]);
  assert.deepEqual(second.map(({ id, competitionRank }) => [id, competitionRank]), first.map(({ id, competitionRank }) => [id, competitionRank]));
});

test("source provenance does not inflate analytic confidence", () => {
  const rich = actor({ targetingEvidence: { references: ["https://one.example", "https://two.example"], owners: ["A", "B"] } });
  const sparse = actor({ id: "G0002", targetingEvidence: { references: [] } });
  const results = scoreActors([rich, sparse], "A", "GB", universes);
  assert.deepEqual(results.map((entry) => entry.analyticConfidence), ["Low", "Low"]);
});

test("campaign recency uses lastSeen only and applies a two-year half-life", () => {
  const ranked = scoreActors([actor()], "A", "GB", universes);
  const [campaign] = relevantCampaigns([{
    id: "C0001",
    name: "Campaign",
    actorIds: ["G0001"],
    lastSeen: "2024-01-02T00:00:00Z",
    modified: "2026-01-01T00:00:00Z",
  }], ranked, new Date("2026-01-01T00:00:00Z"));
  assert.equal(campaign.ageDays, 730);
  assert.equal(campaign.recencyScore, 50);
});

test("missing or future lastSeen values do not produce recency claims", () => {
  const ranked = scoreActors([actor()], "A", "GB", universes);
  const results = relevantCampaigns([
    { id: "C0001", name: "Missing", actorIds: ["G0001"], modified: "2025-12-01T00:00:00Z" },
    { id: "C0002", name: "Future", actorIds: ["G0001"], lastSeen: "2027-01-01T00:00:00Z" },
  ], ranked, new Date("2026-01-01T00:00:00Z"));
  assert.ok(results.every((entry) => entry.recencyScore === null && entry.ageDays === null));
});

test("technique ranking uses the conservative documentation-adjusted coverage", () => {
  const ranked = [
    { ...actor({ id: "G0001", techniques: ["T0001", "T0002", "T0003", "T0004"] }), profileFitExact: 100, fitBand: "Focused match" },
    { ...actor({ id: "G0002", techniques: ["T0001"] }), profileFitExact: 50, fitBand: "Material match" },
  ];
  const results = aggregateTechniques(ranked, [
    { id: "T0001", name: "Shared", tactics: ["initial-access"] },
    { id: "T0002", name: "Broad-documentation penalty", tactics: ["execution"] },
  ]);
  const penalised = results.find((entry) => entry.id === "T0002");
  assert.equal(penalised.weightedCoverage, 66.7);
  assert.equal(penalised.documentationAdjustedCoverage, 50);
  assert.equal(penalised.techniqueScore, 50);
  assert.equal(penalised.operational, true);
});

test("technique output reports incomplete ATT&CK mapping coverage", () => {
  const ranked = [
    { ...actor({ id: "G0001", techniques: ["T0001"] }), profileFitExact: 50, fitBand: "Material match" },
    { ...actor({ id: "G0002", techniques: [] }), profileFitExact: 50, fitBand: "Material match" },
  ];
  const [result] = aggregateTechniques(ranked, [{ id: "T0001", name: "Mapped", tactics: ["execution"] }]);
  assert.equal(result.mappingCompleteness, 50);
});

test("KEV technology filtering is a possible match, never confirmed exposure", () => {
  const entries = [
    { cve: "CVE-1", vendor: "Microsoft", product: "Exchange", name: "Issue", dateAdded: "2026-01-01" },
    { cve: "CVE-2", vendor: "Citrix", product: "NetScaler", name: "Issue", dateAdded: "2026-01-02" },
  ];
  const possible = filterVulnerabilities(entries, "Citrix");
  assert.equal(possible.length, 1);
  assert.equal(possible[0].environmentMatch, "possible");
  assert.equal(possible[0].exposureConfirmed, false);
  assert.equal(filterVulnerabilities(entries, "")[0].environmentMatch, "unknown");
});

test("Navigator export carries the documented scoring method", () => {
  const layer = navigatorLayer("Example", [{ id: "T0001", techniqueScore: 50, actorCount: 2, documentationAdjustedCoverage: 50 }], "17");
  assert.equal(layer.domain, "enterprise-attack");
  assert.equal(layer.techniques[0].score, 50);
  assert.equal(layer.versions.attack, "17");
  assert.match(layer.description, /relevance, not likelihood/i);
});
