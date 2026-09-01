import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertValidCombinedData,
  assertValidNormalisedSource,
  combineSources,
  normaliseAttack,
  normaliseKev,
  normaliseTargeting,
  sourceRecordCount,
} from "./intelligence-lib.mjs";
import {
  assertValidCurrentReports,
  normaliseCurrentReports,
} from "./reporting-lib.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const dataDir = resolve(projectRoot, "public", "data");
const sourceDir = resolve(dataDir, "sources");
const publishedBaseUrl = process.env.PUBLISHED_BASE_URL?.replace(/\/+$/, "") || "";

const sourceDefinitions = {
  attack: {
    name: "MITRE ATT&CK",
    url: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    file: "attack.json",
    normalise: normaliseAttack,
  },
  targeting: {
    name: "MISP Galaxy Tidal Groups",
    url: "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tidal-groups.json",
    file: "targeting.json",
    normalise: normaliseTargeting,
  },
  kev: {
    name: "CISA Known Exploited Vulnerabilities",
    url: "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    file: "kev.json",
    normalise: normaliseKev,
  },
};

const reportSourceDefinitions = [
  {
    id: "ncsc-uk",
    name: "UK NCSC Threat Reports",
    authority: "government",
    url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    homepage: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports",
  },
  {
    id: "cisa-advisories",
    name: "CISA Cybersecurity Advisories",
    authority: "government",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    homepage: "https://www.cisa.gov/news-events/cybersecurity-advisories",
  },
  {
    id: "google-threat-intelligence",
    name: "Google Threat Intelligence",
    authority: "vendor-observed",
    url: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
    homepage: "https://cloud.google.com/blog/topics/threat-intelligence",
  },
  {
    id: "microsoft-threat-intelligence",
    name: "Microsoft Security Blog",
    authority: "vendor-observed",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    homepage: "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/",
  },
];

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function fetchJson(url, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(90000),
      });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);

      const body = await response.text();
      if (body.length < 100) throw new Error("response body is unexpectedly small");
      const data = JSON.parse(body);
      return {
        data,
        metadata: {
          finalUrl: response.url,
          etag: response.headers.get("etag"),
          lastModified: response.headers.get("last-modified"),
          contentLength: body.length,
          sha256: createHash("sha256").update(body).digest("hex"),
        },
      };
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await delay(attempt * 750);
    }
  }
  throw lastError;
}

async function fetchText(url, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, {
        headers: {
          Accept: "application/atom+xml, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
          "User-Agent": "Threat-Profile-Workbench/1.0 (+https://github.com/Promethious666/threat-profile)",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(90000),
      });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      const body = await response.text();
      if (body.length < 100 || !/<(?:rss|feed|rdf:RDF)\b/i.test(body)) {
        throw new Error("response is not a usable syndication feed");
      }
      return body;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await delay(attempt * 750);
    }
  }
  throw lastError;
}

async function readLocal(file) {
  try {
    return JSON.parse(await readFile(resolve(sourceDir, file), "utf8"));
  } catch {
    return null;
  }
}

async function readPublished(file) {
  if (!publishedBaseUrl) return null;
  try {
    return (await fetchJson(`${publishedBaseUrl}/${file}`, 2)).data;
  } catch {
    return null;
  }
}

function validSource(key, value) {
  try {
    assertValidNormalisedSource(key, value);
    return true;
  } catch {
    return false;
  }
}

function validCurrentReports(value) {
  try {
    assertValidCurrentReports(value);
    return true;
  } catch {
    return false;
  }
}

function rejectLargeRegression(key, current, previous) {
  if (!validSource(key, previous)) return;
  const currentCount = sourceRecordCount(key, current);
  const previousCount = sourceRecordCount(key, previous);
  if (currentCount < previousCount * 0.65) {
    throw new Error(`${key} record count fell from ${previousCount} to ${currentCount}`);
  }
}

async function loadSource(key, definition, generatedAt) {
  const published = await readPublished(definition.file);
  const local = await readLocal(definition.file);
  const lastKnownGood = validSource(key, published) ? published : validSource(key, local) ? local : null;

  try {
    const response = await fetchJson(definition.url);
    const normalised = definition.normalise(response.data, generatedAt);
    assertValidNormalisedSource(key, normalised);
    rejectLargeRegression(key, normalised, lastKnownGood);

    return {
      data: normalised,
      health: {
        name: definition.name,
        status: "current",
        checkedAt: generatedAt,
        retrievedAt: generatedAt,
        lastSuccessfulRefresh: generatedAt,
        sourceUrl: definition.url,
        sourceVersion: normalised.version || normalised.catalogVersion || response.metadata.etag || null,
        etag: response.metadata.etag,
        lastModified: response.metadata.lastModified,
        contentLength: response.metadata.contentLength,
        sha256: response.metadata.sha256,
        recordCount: sourceRecordCount(key, normalised),
      },
    };
  } catch (error) {
    if (!lastKnownGood) {
      throw new Error(`${definition.name} refresh failed and no validated last-known-good data is available: ${error.message}`);
    }

    return {
      data: lastKnownGood,
      health: {
        name: definition.name,
        status: "stale",
        checkedAt: generatedAt,
        retrievedAt: null,
        lastSuccessfulRefresh: lastKnownGood.generatedAt || null,
        sourceUrl: definition.url,
        sourceVersion: lastKnownGood.version || lastKnownGood.catalogVersion || null,
        recordCount: sourceRecordCount(key, lastKnownGood),
        error: error.message,
      },
    };
  }
}

async function loadReportFeed(definition, generatedAt) {
  try {
    return {
      ...definition,
      body: await fetchText(definition.url),
      status: "current",
      lastSuccessfulRefresh: generatedAt,
    };
  } catch (error) {
    return {
      ...definition,
      body: "",
      status: "stale",
      lastSuccessfulRefresh: null,
      error: error.cause?.message ? `${error.message}: ${error.cause.message}` : error.message,
    };
  }
}

function mergeReportFallback(current, previous, feedResults) {
  if (!validCurrentReports(previous)) return current;
  const failedIds = new Set(feedResults.filter((result) => result.status !== "current").map((result) => result.id));
  if (!failedIds.size) return current;

  const fallbackReports = previous.reports.filter((report) => failedIds.has(report.source?.id));
  const reports = [...new Map([...current.reports, ...fallbackReports].map((report) => [report.url, report])).values()]
    .sort((a, b) => String(b.publishedAt || "").localeCompare(String(a.publishedAt || "")) || a.title.localeCompare(b.title));
  const previousSources = new Map(previous.sources.map((source) => [source.id, source]));
  const sources = current.sources.map((source) => {
    if (!failedIds.has(source.id)) return source;
    const previousSource = previousSources.get(source.id);
    return {
      ...source,
      lastSuccessfulRefresh: previousSource?.lastSuccessfulRefresh || previous.generatedAt,
      recordCount: reports.filter((report) => report.source?.id === source.id).length,
    };
  });
  return { ...current, sources, reports };
}

await mkdir(sourceDir, { recursive: true });
const generatedAt = new Date().toISOString();
const [attackResult, targetingResult, kevResult] = await Promise.all([
  loadSource("attack", sourceDefinitions.attack, generatedAt),
  loadSource("targeting", sourceDefinitions.targeting, generatedAt),
  loadSource("kev", sourceDefinitions.kev, generatedAt),
]);

const health = [attackResult.health, targetingResult.health, kevResult.health];
const combined = combineSources(
  attackResult.data,
  targetingResult.data,
  kevResult.data,
  health,
  generatedAt,
);
assertValidCombinedData(combined);

const publishedReports = await readPublished("current-reports.json");
const localReports = await readLocal("current-reports.json");
const previousReports = validCurrentReports(publishedReports)
  ? publishedReports
  : validCurrentReports(localReports) ? localReports : null;
const reportFeedResults = await Promise.all(
  reportSourceDefinitions.map((definition) => loadReportFeed(definition, generatedAt)),
);
for (const result of reportFeedResults.filter((entry) => entry.status !== "current")) {
  console.warn(`${result.name} refresh warning: ${result.error}`);
}
const currentReports = mergeReportFallback(
  normaliseCurrentReports(reportFeedResults, combined, generatedAt),
  previousReports,
  reportFeedResults,
);
assertValidCurrentReports(currentReports);

await Promise.all([
  writeFile(resolve(sourceDir, "attack.json"), `${JSON.stringify(attackResult.data, null, 2)}\n`, "utf8"),
  writeFile(resolve(sourceDir, "targeting.json"), `${JSON.stringify(targetingResult.data, null, 2)}\n`, "utf8"),
  writeFile(resolve(sourceDir, "kev.json"), `${JSON.stringify(kevResult.data, null, 2)}\n`, "utf8"),
  writeFile(resolve(sourceDir, "current-reports.json"), `${JSON.stringify(currentReports, null, 2)}\n`, "utf8"),
  writeFile(resolve(dataDir, "intelligence.json"), `${JSON.stringify(combined, null, 2)}\n`, "utf8"),
]);

console.log(
  `Updated ${combined.actors.length} actors, ${combined.campaigns.length} campaigns, ` +
  `${combined.techniques.length} techniques, ${combined.vulnerabilities.length} KEV entries and ` +
  `${currentReports.reports.length} current public reports.`,
);
