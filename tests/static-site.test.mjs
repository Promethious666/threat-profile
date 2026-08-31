import test from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const html = await readFile(resolve(root, "pages-src", "index.html"), "utf8");
const app = await readFile(resolve(root, "pages-src", "app.js"), "utf8");
const css = await readFile(resolve(root, "pages-src", "styles.css"), "utf8");

test("every static DOM selector used by the application exists once", () => {
  const usedIds = [...app.matchAll(/document\.querySelector\("#([A-Za-z0-9_-]+)"\)/g)].map((match) => match[1]);
  const declaredIds = [...html.matchAll(/\sid="([A-Za-z0-9_-]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(declaredIds).size, declaredIds.length, "HTML contains duplicate IDs");
  for (const id of usedIds) {
    assert.equal(declaredIds.filter((candidate) => candidate === id).length, 1, `Missing or duplicate #${id}`);
  }
});

test("view navigation and panels have a one-to-one mapping", () => {
  const views = [...html.matchAll(/\sdata-view="([A-Za-z0-9_-]+)"/g)].map((match) => match[1]);
  const panels = [...html.matchAll(/\sdata-panel="([A-Za-z0-9_-]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(views)].sort(), [...new Set(panels)].sort());
});

test("critical accessibility and sharing metadata are present", () => {
  assert.match(html, /class="skip-link"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(html, /property="og:image"/);
  assert.match(html, /name="twitter:card" content="summary_large_image"/);
});

test("onboarding and local report export are present and privacy-labelled", () => {
  assert.equal([...html.matchAll(/<li><span>[123]<\/span><div><strong>/g)].length, 3);
  assert.match(html, /id="print-report-output"/);
  assert.match(html, /id="report-content"/);
  assert.match(html, /includes any organisation and technology text entered/i);
  assert.match(app, /window\.print\(\)/);
  assert.match(app, /window\.addEventListener\("beforeprint"/);
  assert.match(app, /Possible text match|possible text match/i);
  assert.match(css, /#results > :not\(\.print-report\)/);
  assert.match(css, /@page/);
});

test("all local entry assets exist", async () => {
  const references = [...html.matchAll(/(?:href|src)="\.\/([^"?#]+)"/g)].map((match) => match[1]);
  for (const reference of references) await access(resolve(root, "pages-src", reference));
});
