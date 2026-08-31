import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertValidCombinedData, assertValidCurrentSignals } from "./intelligence-lib.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const output = resolve(projectRoot, "docs");

const intelligence = JSON.parse(
  await readFile(resolve(projectRoot, "public", "data", "intelligence.json"), "utf8"),
);
const currentSignals = JSON.parse(
  await readFile(resolve(projectRoot, "public", "data", "sources", "current-threat-signals.json"), "utf8"),
);
assertValidCombinedData(intelligence);
assertValidCurrentSignals(currentSignals);

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

await cp(resolve(projectRoot, "pages-src"), output, { recursive: true });
await cp(resolve(projectRoot, "public", "data"), resolve(output, "data"), { recursive: true });
await writeFile(resolve(output, ".nojekyll"), "", "utf8");

console.log(`Built ${output}`);
