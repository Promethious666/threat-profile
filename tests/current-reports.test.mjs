import test from "node:test";
import assert from "node:assert/strict";
import {
  assertValidCurrentReports,
  normaliseCurrentReports,
  parseSyndicationFeed,
  validateCurrentReports,
} from "../scripts/reporting-lib.mjs";
import { groupCurrentEntities, matchCurrentReports } from "../pages-src/lib.js";

const rss = `<?xml version="1.0"?>
<rss version="2.0"><channel><title>Example</title><item>
  <title><![CDATA[Example Group campaign targets UK financial services]]></title>
  <link>https://example.test/reports/example-group</link>
  <pubDate>Mon, 31 Aug 2026 10:00:00 GMT</pubDate>
  <description><![CDATA[ExampleRansom affected a British financial institution using a cloud service.]]></description>
</item></channel></rss>`;

const atom = `<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom"><entry>
  <title>Technology advisory</title>
  <link href="https://example.test/reports/technology" />
  <updated>2026-08-30T10:00:00Z</updated>
  <summary>Guidance for technology companies.</summary>
</entry></feed>`;

const intelligence = {
  actors: [{ id: "G9999", name: "Example Group", aliases: ["Example Crew"] }],
  software: [{ id: "S9999", name: "ExampleRansom", kind: "malware" }],
  sectors: ["Financial Services", "Technology"],
  countries: ["GB", "US"],
};

test("RSS and Atom entries are parsed into bounded report records", () => {
  assert.deepEqual(parseSyndicationFeed(rss), [{
    title: "Example Group campaign targets UK financial services",
    url: "https://example.test/reports/example-group",
    publishedAt: "2026-08-31",
    summary: "ExampleRansom affected a British financial institution using a cloud service.",
  }]);
  assert.equal(parseSyndicationFeed(atom)[0].publishedAt, "2026-08-30");
});

test("automated reports correlate entities, sector and country from the same source record", () => {
  const result = normaliseCurrentReports([
    { id: "one", name: "One", authority: "government", url: "https://example.test/one.xml", homepage: "https://example.test/one", body: rss },
    { id: "two", name: "Two", authority: "government", url: "https://example.test/two.xml", homepage: "https://example.test/two", body: atom },
    { id: "three", name: "Three", authority: "vendor-observed", url: "https://example.test/three.xml", homepage: "https://example.test/three", body: atom },
  ], intelligence, "2026-09-01T00:00:00Z");

  const report = result.reports.find((entry) => entry.url.endsWith("/example-group"));
  assert.equal(report.activityType, "campaign-report");
  assert.deepEqual(report.entities.map(({ id }) => id).sort(), ["G9999", "S9999"]);
  assert.deepEqual(report.sectors, ["Financial Services"]);
  assert.deepEqual(report.countries, ["GB"]);
  assert.doesNotThrow(() => assertValidCurrentReports(result));
});

test("current-report validation rejects unsafe or incomplete snapshots", () => {
  const invalid = {
    schemaVersion: 1,
    generatedAt: "2026-09-01T00:00:00Z",
    sources: [{}, {}, {}],
    reports: [{ id: "bad", title: "", publishedAt: "not-a-date", url: "http://example.test", entities: [], sectors: [], countries: [] }],
  };
  assert.ok(validateCurrentReports(invalid).length >= 4);
});

test("new uppercase vendor actor names are discovered without a curated actor list", () => {
  const feed = rss
    .replace("Example Group campaign targets UK financial services", "EMBER FALCON Targets UK financial services")
    .replaceAll("ExampleRansom", "previously unseen tooling");
  const result = normaliseCurrentReports([
    { id: "one", name: "One", authority: "vendor-observed", url: "https://example.test/one.xml", homepage: "https://example.test/one", body: feed },
  ], { ...intelligence, actors: [], software: [] }, "2026-09-01T00:00:00Z");
  assert.deepEqual(result.reports[0].entities.map(({ name, entityType }) => ({ name, entityType })), [
    { name: "EMBER FALCON", entityType: "unmapped-threat-actor" },
  ]);
});

test("profile matching never turns a country-only mention into sector relevance", () => {
  const reports = [
    { id: "country", title: "Example Group activity in the UK", summary: "Government warning.", sectors: [], countries: ["GB"], entities: [] },
    { id: "joint", title: "UK financial services warning", summary: "Example Group campaign.", sectors: ["Financial Services"], countries: ["GB"], entities: [{ id: "G9999", name: "Example Group", entityType: "threat-actor-group" }] },
  ];
  const matches = matchCurrentReports(reports, { sector: "Financial Services", country: "GB" });
  assert.deepEqual(matches.map(({ id }) => id), ["joint"]);
  assert.equal(matches[0].evidenceClass, "observed-context");
  assert.deepEqual(groupCurrentEntities(matches).map(({ id }) => id), ["G9999"]);
});
