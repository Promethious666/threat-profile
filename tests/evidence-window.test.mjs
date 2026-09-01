import test from "node:test";
import assert from "node:assert/strict";
import {
  EVIDENCE_WINDOW_PRESETS,
  TOP_FOCUS_VALUES,
  aggregateSoftware,
  aggregateTechniques,
  classifyCampaignsByWindow,
  classifyKevsByWindow,
  classifyReportsByWindow,
  createEvidenceWindow,
  normalizeEvidenceWindowPreset,
  normalizeTopFocus,
  relevantCampaigns,
  selectTopFocus,
} from "../pages-src/lib.js";
import { detectionsForTechnique } from "../pages-src/detections.js";

test("evidence-window presets include every approved choice", () => {
  assert.deepEqual(Object.keys(EVIDENCE_WINDOW_PRESETS), [
    "7d", "14d", "1m", "3m", "6m", "12m", "24m", "36m", "all",
  ]);
  assert.equal(normalizeEvidenceWindowPreset("1 week"), "7d");
  assert.equal(normalizeEvidenceWindowPreset("2-weeks"), "14d");
  assert.equal(normalizeEvidenceWindowPreset("3 months"), "3m");
  assert.equal(normalizeEvidenceWindowPreset("2 years"), "24m");
  assert.equal(normalizeEvidenceWindowPreset("not-a-window"), "24m");
  assert.equal(normalizeEvidenceWindowPreset("not-a-window", "6m"), "6m");
});

test("cutoffs use an explicit asOf date ahead of generatedAt and UTC-day granularity", () => {
  const window = createEvidenceWindow("7d", {
    generatedAt: "2025-01-01T01:00:00-08:00",
    asOf: "2026-08-31T23:45:00+01:00",
  });
  assert.equal(window.referenceSource, "asOf");
  assert.equal(window.asOf, "2026-08-31T00:00:00.000Z");
  assert.equal(window.cutoff, "2026-08-24T00:00:00.000Z");
  assert.equal(window.granularity, "utc-day");
});

test("month windows use calendar months and clamp leap-year month ends", () => {
  const oneMonth = createEvidenceWindow("1m", { generatedAt: "2024-03-31T12:00:00Z" });
  const threeMonths = createEvidenceWindow("3m", { generatedAt: "2026-08-31T12:00:00Z" });
  assert.equal(oneMonth.cutoff, "2024-02-29T00:00:00.000Z");
  assert.equal(threeMonths.cutoff, "2026-05-31T00:00:00.000Z");
  assert.equal(createEvidenceWindow("all", { generatedAt: "2026-08-31" }).cutoff, null);
});

test("a reproducible evidence window requires a valid generatedAt or asOf date", () => {
  assert.throws(() => createEvidenceWindow("7d"), /valid generatedAt date/i);
  assert.throws(
    () => createEvidenceWindow("7d", { generatedAt: "2026-08-31", asOf: "not-a-date" }),
    /valid asOf date/i,
  );
});

test("campaign classification uses lastSeen and preserves every evidence class", () => {
  const campaigns = [
    { id: "boundary", lastSeen: "2026-08-24" },
    { id: "recent", lastSeen: "2026-08-30T23:59:00Z" },
    { id: "old", lastSeen: "2026-08-23" },
    { id: "missing" },
    { id: "invalid", lastSeen: "2026-02-30" },
    { id: "future", lastSeen: "2026-09-01" },
  ];
  const result = classifyCampaignsByWindow(campaigns, "7d", { asOf: "2026-08-31T12:00:00Z" });

  assert.deepEqual(result.inWindow.map(({ id }) => id), ["boundary", "recent"]);
  assert.deepEqual(result.outOfWindow.map(({ id }) => id), ["old"]);
  assert.deepEqual(result.undated.map(({ id }) => id), ["missing"]);
  assert.deepEqual(result.invalid.map(({ id }) => id), ["invalid"]);
  assert.deepEqual(result.future.map(({ id }) => id), ["future"]);
  assert.equal(result.all.length, campaigns.length);
  assert.equal(result.excluded.length, 4);
  assert.equal(campaigns[0].evidenceWindow, undefined, "source records are not mutated");
});

test("all available still excludes undated and future campaigns from in-window claims", () => {
  const result = classifyCampaignsByWindow([
    { id: "historical", lastSeen: "2018-01-01" },
    { id: "missing" },
    { id: "future", lastSeen: "2027-01-01" },
  ], "all", { generatedAt: "2026-08-31" });
  assert.deepEqual(result.inWindow.map(({ id }) => id), ["historical"]);
  assert.deepEqual(result.excluded.map(({ id }) => id), ["missing", "future"]);
  assert.equal(result.outOfWindow.length, 0);
});

test("KEV classification uses dateAdded with an inclusive cutoff date", () => {
  const result = classifyKevsByWindow([
    { cve: "CVE-IN", dateAdded: "2026-08-17" },
    { cve: "CVE-OUT", dateAdded: "2026-08-16" },
    { cve: "CVE-FUTURE", dateAdded: "2026-09-01" },
  ], "14d", { generatedAt: "2026-08-31T21:30:00Z" });
  assert.deepEqual(result.inWindow.map(({ cve }) => cve), ["CVE-IN"]);
  assert.deepEqual(result.outOfWindow.map(({ cve }) => cve), ["CVE-OUT"]);
  assert.deepEqual(result.future.map(({ cve }) => cve), ["CVE-FUTURE"]);
});

test("current-report classification uses source publication dates without inventing activity dates", () => {
  const result = classifyReportsByWindow([
    { id: "recent-publication", publishedAt: "2026-08-30", observedAt: null },
    { id: "older-publication", publishedAt: "2026-05-01", observedAt: "2026-08-30" },
    { id: "undated", publishedAt: null, observedAt: "2026-08-30" },
  ], "3m", { generatedAt: "2026-08-31" });

  assert.deepEqual(result.inWindow.map(({ id }) => id), ["recent-publication"]);
  assert.deepEqual(result.outOfWindow.map(({ id }) => id), ["older-publication"]);
  assert.deepEqual(result.undated.map(({ id }) => id), ["undated"]);
  assert.ok(result.all.every((report) => report.evidenceWindow.field === "publishedAt"));
});

test("Top-N focus accepts only the approved values and preserves cutoff ties", () => {
  assert.deepEqual(TOP_FOCUS_VALUES, [5, 10, 15, 20, 25]);
  assert.equal(normalizeTopFocus("Top 25"), 25);
  assert.equal(normalizeTopFocus("17"), 10);
  assert.equal(normalizeTopFocus("17", 20), 20);

  const ranked = Array.from({ length: 30 }, (_, index) => ({ competitionRank: index + 1 }));
  ranked[25].competitionRank = 25;
  const selection = selectTopFocus(ranked, 25);
  assert.equal(selection.requestedCount, 25);
  assert.equal(selection.actualCount, 26);
  assert.equal(selection.cutoffRank, 25);
  assert.equal(selection.includedCutoffTies, true);
  assert.equal(selection.focused.at(-1).competitionRank, 25);
  assert.equal(selection.remaining[0].competitionRank, 27);
  assert.equal(ranked.length, 30);
});

test("Top-N focus reports an empty selection without inventing a cutoff rank", () => {
  assert.deepEqual(selectTopFocus([], 10), {
    requestedCount: 10,
    actualCount: 0,
    cutoffRank: null,
    includedCutoffTies: false,
    focused: [],
    remaining: [],
  });
});

test("changing Top-N recalculates techniques, software, campaigns and mapped KQL priorities", () => {
  const actors = Array.from({ length: 25 }, (_, index) => ({
    id: `G${String(index + 1).padStart(4, "0")}`,
    name: `Actor ${index + 1}`,
    competitionRank: index + 1,
    profileFitExact: 100 - index,
    profileFit: 100 - index,
    fitBand: "Focused match",
    techniques: [index === 5 ? "T1078" : `T9${String(index).padStart(3, "0")}`],
    software: [`S${String(index).padStart(4, "0")}`],
  }));
  const techniques = actors.map((actor) => ({ id: actor.techniques[0], name: actor.techniques[0], tactics: ["initial-access"] }));
  const software = actors.map((actor) => ({ id: actor.software[0], name: actor.software[0] }));
  const campaigns = actors.map((actor, index) => ({ id: `C${index}`, actorIds: [actor.id], lastSeen: "2026-08-01" }));

  const topFive = selectTopFocus(actors, 5).focused;
  const topTwentyFive = selectTopFocus(actors, 25).focused;
  const fiveTechniques = aggregateTechniques(topFive, techniques);
  const twentyFiveTechniques = aggregateTechniques(topTwentyFive, techniques);

  assert.equal(fiveTechniques.length, 5);
  assert.equal(twentyFiveTechniques.length, 25);
  assert.equal(aggregateSoftware(topFive, software).length, 5);
  assert.equal(aggregateSoftware(topTwentyFive, software).length, 25);
  assert.equal(relevantCampaigns(campaigns, topFive, "2026-08-31").length, 5);
  assert.equal(relevantCampaigns(campaigns, topTwentyFive, "2026-08-31").length, 25);
  assert.equal(fiveTechniques.some((technique) => detectionsForTechnique(technique.id).length), false);
  assert.equal(twentyFiveTechniques.some((technique) => detectionsForTechnique(technique.id).length), true);
});
