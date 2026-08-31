import test from "node:test";
import assert from "node:assert/strict";
import { DETECTIONS, detectionsForTechnique } from "../pages-src/detections.js";

test("the KQL catalogue contains ten uniquely identified, fully documented hunting starters", () => {
  assert.equal(DETECTIONS.length, 10);
  assert.equal(new Set(DETECTIONS.map((entry) => entry.id)).size, DETECTIONS.length);
  for (const detection of DETECTIONS) {
    assert.equal(detection.status, "Schema reviewed · Tenant validation required");
    assert.match(detection.schemaVerifiedAt, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(detection.title && detection.purpose && detection.targetProduct && detection.lookback);
    assert.ok(detection.techniqueIds.length && detection.tables.length && detection.prerequisites.length);
    assert.ok(detection.expectedFields.length && detection.falsePositives.length && detection.tuning.length && detection.validationSteps.length);
    assert.ok(detection.documentationLinks.length);
    assert.ok(detection.documentationLinks.every(({ url }) => url.startsWith("https://learn.microsoft.com/")));
    assert.ok(detection.kql.length > 80);
  }
});

test("critical Microsoft schema literals are represented exactly", () => {
  const signin = DETECTIONS.find(({ id }) => id === "risky-interactive-signin");
  const rdp = DETECTIONS.find(({ id }) => id === "public-rdp-local-admin");
  const network = DETECTIONS.find(({ id }) => id === "rare-interpreter-network");
  assert.match(signin.kql, /ResultType == "0"/);
  assert.match(rdp.kql, /LogonType == "RemoteInteractive"/);
  assert.match(network.kql, /ActionType == "ConnectionSuccess"/);
});

test("event-level Defender queries retain identifiers needed for investigation", () => {
  const eventLevel = DETECTIONS.filter((entry) =>
    (entry.targetProduct.includes("Defender XDR") && !entry.kql.includes("| summarize")) || entry.id === "delivered-qr-phish");
  for (const detection of eventLevel) assert.match(detection.kql, /ReportId/);
  for (const id of ["office-child-process", "public-rdp-local-admin", "startup-folder-persistence", "controlled-folder-access"]) {
    assert.match(DETECTIONS.find((entry) => entry.id === id).kql, /DeviceId/);
  }
});

test("technique lookup includes parent and sub-technique relationships", () => {
  assert.ok(detectionsForTechnique("T1566").some(({ id }) => id === "delivered-qr-phish"));
  assert.ok(detectionsForTechnique("T1566.002").some(({ id }) => id === "delivered-qr-phish"));
});
