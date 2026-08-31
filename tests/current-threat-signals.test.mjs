import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { classifySignalsByWindow } from "../pages-src/lib.js";
import { assertValidCurrentSignals, validateCurrentSignals } from "../scripts/intelligence-lib.mjs";

const root = resolve(import.meta.dirname, "..");
const file = resolve(root, "public", "data", "sources", "current-threat-signals.json");
const data = JSON.parse(await readFile(file, "utf8"));
const intelligence = JSON.parse(await readFile(resolve(root, "public", "data", "intelligence.json"), "utf8"));

const entityTypes = new Set(["threat-actor-group", "ransomware-family"]);
const evidenceTiers = new Set([
  "vendor-observed",
  "law-enforcement-assessed",
  "government-warning",
  "authoritative-catalogue",
]);
const intersectionStatuses = new Set(["confirmed", "not-established", "not-applicable"]);
const confidences = new Set(["high", "medium", "low"]);
const datePattern = /^\d{4}-\d{2}-\d{2}$/;

function assertDate(value, field, { nullable = false } = {}) {
  if (nullable && value === null) return;
  assert.match(value, datePattern, `${field} must use YYYY-MM-DD`);
  assert.equal(new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10), value, `${field} must be a real date`);
}

function assertText(value, field) {
  assert.equal(typeof value, "string", `${field} must be a string`);
  assert.ok(value.trim().length > 0, `${field} must not be empty`);
}

test("current threat signals follow the dated provenance schema", () => {
  assert.equal(data.schemaVersion, 1);
  assertDate(data.reviewedAt, "reviewedAt");
  assert.ok(data.signals.length >= 3);
  assert.deepEqual(new Set(Object.keys(data.evidenceTiers)), evidenceTiers);

  const ids = new Set();
  for (const signal of data.signals) {
    assert.match(signal.id, /^ctp-\d{4}-\d{2}-\d{2}-[a-z0-9-]+$/);
    assert.ok(!ids.has(signal.id), `duplicate signal id: ${signal.id}`);
    ids.add(signal.id);

    assert.match(signal.entityId, /^[GS]\d{4}$/);
    assertText(signal.entityName, `${signal.id}.entityName`);
    assert.ok(entityTypes.has(signal.entityType), `${signal.id} has an unsupported entity type`);
    assert.ok(Array.isArray(signal.aliases));
    assert.equal(new Set(signal.aliases).size, signal.aliases.length, `${signal.id} has duplicate aliases`);

    assertDate(signal.publishedAt, `${signal.id}.publishedAt`, { nullable: true });
    assertDate(signal.observedAt, `${signal.id}.observedAt`, { nullable: true });
    assertDate(signal.sourceUpdatedAt, `${signal.id}.sourceUpdatedAt`, { nullable: true });
    assert.ok(signal.publishedAt || signal.observedAt, `${signal.id} needs a published or observed date`);
    assert.ok((signal.publishedAt || signal.observedAt) <= data.reviewedAt, `${signal.id} is dated after review`);
    assertText(signal.dateBasis, `${signal.id}.dateBasis`);

    assert.ok(evidenceTiers.has(signal.evidenceTier), `${signal.id} has an unsupported evidence tier`);
    assert.ok(intersectionStatuses.has(signal.intersectionStatus), `${signal.id} needs an intersection status`);
    assertText(signal.summary, `${signal.id}.summary`);
    assertText(signal.status, `${signal.id}.status`);

    assert.ok(Array.isArray(signal.sectorClaims));
    assert.ok(Array.isArray(signal.countryClaims));
    for (const claim of signal.sectorClaims) {
      assertText(claim.sector, `${signal.id}.sector`);
      assertText(claim.relationship, `${signal.id}.sector relationship`);
      assert.ok(confidences.has(claim.confidence), `${signal.id} has invalid sector confidence`);
      assertText(claim.claim, `${signal.id}.sector claim`);
    }
    for (const claim of signal.countryClaims) {
      assert.match(claim.countryCode, /^[A-Z]{2}$/);
      assertText(claim.country, `${signal.id}.country`);
      assertText(claim.relationship, `${signal.id}.country relationship`);
      assert.ok(confidences.has(claim.confidence), `${signal.id} has invalid country confidence`);
      assertText(claim.claim, `${signal.id}.country claim`);
    }

    assertText(signal.source.name, `${signal.id}.source.name`);
    assert.match(signal.source.url, /^https:\/\//);
    assert.match(signal.entityReference, /^https:\/\/attack\.mitre\.org\/(?:groups|software)\/[GS]\d{4}\/$/);
    assert.ok(Array.isArray(signal.caveats) && signal.caveats.length > 0, `${signal.id} needs caveats`);
    signal.caveats.forEach((caveat, index) => assertText(caveat, `${signal.id}.caveats[${index}]`));
  }
});

test("entity identity and UK-finance intersection safeguards are explicit", () => {
  const names = new Set(data.signals.map((signal) => signal.entityName));
  assert.ok(names.has("Scattered Spider"));
  assert.ok(names.has("ShinyHunters"));
  assert.ok(names.has("Qilin"));

  const shinyHunters = data.signals.find((signal) => signal.entityName === "ShinyHunters");
  const qilin = data.signals.find((signal) => signal.entityName === "Qilin");
  assert.equal(shinyHunters.entityType, "threat-actor-group");
  assert.ok(!shinyHunters.aliases.includes("Scattered Spider"), "related groups must not be encoded as aliases");
  assert.equal(qilin.entityId, "S1242");
  assert.equal(qilin.entityType, "ransomware-family", "Qilin must not be presented as a threat actor");

  for (const signal of data.signals) {
    const hasSectorAndCountry = signal.sectorClaims.length > 0 && signal.countryClaims.length > 0;
    if (hasSectorAndCountry) {
      assert.equal(
        signal.intersectionStatus,
        "not-established",
        `${signal.id} must not imply a confirmed sector-country intersection`,
      );
      assert.ok(
        signal.caveats.some((caveat) => /do not establish|does not establish/i.test(caveat)),
        `${signal.id} must explain the unproven intersection`,
      );
    }
  }
});

test("the default UK financial-services profile surfaces all three expected entities", () => {
  const matches = data.signals.filter((signal) =>
    signal.sectorClaims.some((claim) => claim.sector === "Financial Services") ||
    signal.countryClaims.some((claim) => claim.countryCode === "GB"));
  const inDefaultWindow = classifySignalsByWindow(matches, "24m", { generatedAt: intelligence.generatedAt }).inWindow;
  const names = new Set(inDefaultWindow.map((signal) => signal.entityName));
  assert.ok(names.has("Scattered Spider"));
  assert.ok(names.has("ShinyHunters"));
  assert.ok(names.has("Qilin"));
});

test("signals use only the reviewed authoritative source set", () => {
  const allowedHosts = new Set([
    "cloud.google.com",
    "www.ic3.gov",
    "attack.mitre.org",
    "www.nationalcrimeagency.gov.uk",
  ]);

  for (const signal of data.signals) {
    assert.ok(allowedHosts.has(new URL(signal.source.url).hostname), `${signal.id} uses an unreviewed source host`);
  }
});

test("the build validator accepts the reviewed layer and rejects unsafe scope claims", () => {
  assert.doesNotThrow(() => assertValidCurrentSignals(data));
  const invalid = structuredClone(data);
  invalid.signals[0].intersectionStatus = "confirmed";
  assert.ok(validateCurrentSignals(invalid).some((error) => /unproven sector-country intersection/i.test(error)));

  invalid.signals[0].intersectionStatus = "not-established";
  invalid.signals[0].publishedAt = "2026-99-99";
  assert.ok(validateCurrentSignals(invalid).some((error) => /valid source publication date/i.test(error)));
});
