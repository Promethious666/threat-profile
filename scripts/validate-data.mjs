import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertValidCombinedData,
  assertValidNormalisedSource,
} from "./intelligence-lib.mjs";
import { assertValidCurrentReports } from "./reporting-lib.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const dataDir = resolve(projectRoot, "public", "data");

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

const [attack, targeting, kev, currentReports, combined] = await Promise.all([
  readJson(resolve(dataDir, "sources", "attack.json")),
  readJson(resolve(dataDir, "sources", "targeting.json")),
  readJson(resolve(dataDir, "sources", "kev.json")),
  readJson(resolve(dataDir, "sources", "current-reports.json")),
  readJson(resolve(dataDir, "intelligence.json")),
]);

assertValidNormalisedSource("attack", attack);
assertValidNormalisedSource("targeting", targeting);
assertValidNormalisedSource("kev", kev);
assertValidCurrentReports(currentReports);
assertValidCombinedData(combined);

console.log(
  `Validated ${combined.actors.length} actors, ${combined.techniques.length} techniques, ` +
  `${combined.campaigns.length} campaigns, ${combined.vulnerabilities.length} KEV entries and ` +
  `${currentReports.reports.length} current public reports.`,
);
