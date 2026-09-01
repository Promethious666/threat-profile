import { DETECTIONS, detectionsForTechnique } from "./detections.js";
import {
  EVIDENCE_WINDOW_PRESETS,
  aggregateSoftware,
  aggregateTechniques,
  attackTechniqueUrl,
  classifyCampaignsByWindow,
  classifyKevsByWindow,
  classifyReportsByWindow,
  filterVulnerabilities,
  groupCurrentEntities,
  matchCurrentReports,
  navigatorLayer,
  normalizeEvidenceWindowPreset,
  normalizeTopFocus,
  relevantCampaigns,
  scoreActors,
  selectTopFocus,
} from "./lib.js";

const elements = {
  main: document.querySelector("#main-content"),
  form: document.querySelector("#profile-form"),
  organisation: document.querySelector("#organisation"),
  sector: document.querySelector("#sector"),
  country: document.querySelector("#country"),
  technology: document.querySelector("#technology"),
  watchlist: document.querySelector("#watchlist"),
  evidenceWindow: document.querySelector("#evidence-window"),
  focusCount: document.querySelector("#focus-count"),
  analyseButton: document.querySelector("#analyse-button"),
  profileBuilder: document.querySelector("#profile-builder"),
  profileMode: document.querySelector("#profile-mode"),
  editProfile: document.querySelector("#edit-profile"),
  results: document.querySelector("#results"),
  error: document.querySelector("#error-panel"),
  errorMessage: document.querySelector("#error-message"),
  retryButton: document.querySelector("#retry-button"),
  statusRegion: document.querySelector("#status-region"),
  feedback: document.querySelector("#action-feedback"),
  healthButton: document.querySelector("#health-button"),
  healthPopover: document.querySelector("#health-popover"),
  healthDot: document.querySelector("#health-dot"),
  healthLabel: document.querySelector("#health-label"),
  healthSummary: document.querySelector("#health-summary"),
  healthGrid: document.querySelector("#health-grid"),
  generatedAt: document.querySelector("#generated-at"),
  coverageGrid: document.querySelector("#coverage-grid"),
  shareProfile: document.querySelector("#share-profile"),
  profileTitle: document.querySelector("#profile-title"),
  profileBasis: document.querySelector("#profile-basis"),
  profileDate: document.querySelector("#profile-date"),
  scopeBadge: document.querySelector("#scope-badge"),
  windowBadge: document.querySelector("#window-badge"),
  focusBadge: document.querySelector("#focus-badge"),
  judgementGrid: document.querySelector("#judgement-grid"),
  priorityActions: document.querySelector("#priority-actions"),
  overviewScope: document.querySelector("#overview-scope"),
  overviewReports: document.querySelector("#overview-reports"),
  overviewActors: document.querySelector("#overview-actors"),
  overviewTechniques: document.querySelector("#overview-techniques"),
  overviewCampaigns: document.querySelector("#overview-campaigns"),
  overviewExposure: document.querySelector("#overview-exposure"),
  overviewGaps: document.querySelector("#overview-gaps"),
  currentReportCount: document.querySelector("#current-report-count"),
  currentReportList: document.querySelector("#current-report-list"),
  actorSearch: document.querySelector("#actor-search"),
  actorBandFilter: document.querySelector("#actor-band-filter"),
  clearActorFilters: document.querySelector("#clear-actor-filters"),
  actorCount: document.querySelector("#actor-count"),
  actorList: document.querySelector("#actor-list"),
  actorMore: document.querySelector("#actor-more"),
  actorDetail: document.querySelector("#actor-detail"),
  campaignCount: document.querySelector("#campaign-count"),
  campaignList: document.querySelector("#campaign-list"),
  techniqueSearch: document.querySelector("#technique-search"),
  tacticFilter: document.querySelector("#tactic-filter"),
  detectionFilter: document.querySelector("#detection-filter"),
  clearTechniqueFilters: document.querySelector("#clear-technique-filters"),
  techniqueCount: document.querySelector("#technique-count"),
  techniqueList: document.querySelector("#technique-list"),
  techniqueMore: document.querySelector("#technique-more"),
  techniqueDetail: document.querySelector("#technique-detail"),
  kevContext: document.querySelector("#kev-context"),
  exposureBanner: document.querySelector("#exposure-banner"),
  kevCount: document.querySelector("#kev-count"),
  kevList: document.querySelector("#kev-list"),
  kevMore: document.querySelector("#kev-more"),
  modelActorSelect: document.querySelector("#model-actor-select"),
  diamondView: document.querySelector("#diamond-view"),
  pyramidView: document.querySelector("#pyramid-view"),
  exportProfile: document.querySelector("#export-profile"),
  exportAttack: document.querySelector("#export-attack"),
  reportContent: document.querySelector("#report-content"),
};

const state = {
  intelligence: null,
  currentReportData: null,
  profile: null,
  rankedActors: [],
  focusSelection: null,
  focusActors: [],
  techniques: [],
  software: [],
  campaigns: [],
  campaignEvidence: null,
  vulnerabilities: [],
  kevEvidence: null,
  currentReports: [],
  reportEvidence: null,
  currentEntities: [],
  activeView: "overview",
  selectedActorId: null,
  selectedTechniqueId: null,
  actorVisible: 10,
  techniqueVisible: 20,
  kevVisible: 12,
  exampleProfile: true,
};

const regionNames = new Intl.DisplayNames(["en"], { type: "region" });
let feedbackTimer;
const screenDocumentTitle = document.title;
const validViews = new Set([...document.querySelectorAll("[data-panel]")].map((panel) => panel.dataset.panel));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeUrl(value) {
  const raw = String(value || "").trim();
  if (!raw || /[\u0000-\u001F\u007F"<>\\]/.test(raw)) return "";
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password) return "";
    return url.href;
  } catch {
    return "";
  }
}

function externalLink(value, label) {
  const url = safeUrl(value);
  return url
    ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`
    : "";
}

function displayRegion(code) {
  try {
    return regionNames.of(code) || code;
  } catch {
    return code;
  }
}

function formatDate(value, includeTime = false) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    ...(includeTime ? { timeStyle: "short" } : {}),
    timeZone: "UTC",
  }).format(date) + (includeTime ? " UTC" : "");
}

function relativeAge(value) {
  if (!value) return "age unknown";
  const milliseconds = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(milliseconds)) return "age unknown";
  const hours = Math.max(0, Math.floor(milliseconds / 3600000));
  if (hours < 1) return "less than an hour ago";
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function slugClass(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function fitBandClass(value) {
  return {
    "Focused match": "focused",
    "Material match": "material",
    "Broad match": "broad",
  }[value] || "";
}

function sourceLinks(references, label = "Open supporting source") {
  const links = (references || []).map(safeUrl).filter(Boolean).slice(0, 4);
  if (!links.length) return '<span class="muted">No assertion-level citation retained</span>';
  return links.map((url, index) =>
    externalLink(url, `${label}${links.length > 1 ? ` ${index + 1}` : ""}`)).join("");
}

function profileName() {
  return state.profile?.organisation || `${state.profile?.sector || ""} · ${displayRegion(state.profile?.country || "")}`;
}

function publicProfileName() {
  return `${state.profile?.sector || ""} · ${displayRegion(state.profile?.country || "")}`;
}

function evidenceWindowLabel() {
  return state.campaignEvidence?.window?.label || EVIDENCE_WINDOW_PRESETS[state.profile?.evidenceWindow]?.label || "24 months";
}

function focusLabel() {
  if (!state.focusSelection) return "Top 10";
  const ties = state.focusSelection.includedCutoffTies
    ? ` + ${state.focusSelection.actualCount - state.focusSelection.requestedCount} cutoff tie${state.focusSelection.actualCount - state.focusSelection.requestedCount === 1 ? "" : "s"}`
    : "";
  return `Top ${state.focusSelection.requestedCount}${ties}`;
}

function humanise(value) {
  return String(value || "Unknown").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function summarise(value, maximum) {
  const text = String(value || "").trim();
  return text.length > maximum ? `${text.slice(0, maximum - 1).trimEnd()}…` : text;
}

function showFeedback(message) {
  clearTimeout(feedbackTimer);
  elements.feedback.textContent = message;
  elements.feedback.hidden = false;
  feedbackTimer = setTimeout(() => {
    elements.feedback.hidden = true;
  }, 4200);
}

function announce(message) {
  elements.statusRegion.textContent = "";
  requestAnimationFrame(() => {
    elements.statusRegion.textContent = message;
  });
}

function downloadJson(filename, data) {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function copyText(value, successMessage) {
  try {
    await navigator.clipboard.writeText(value);
    showFeedback(successMessage);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.className = "clipboard-fallback";
    document.body.append(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    showFeedback(copied ? successMessage : "Copy failed. Select and copy the content manually.");
  }
}

function currentUrl() {
  const url = new URL(location.href);
  url.search = "";
  url.hash = "";
  url.searchParams.set("v", "2");
  if (state.profile?.sector) url.searchParams.set("sector", state.profile.sector);
  if (state.profile?.country) url.searchParams.set("country", state.profile.country);
  url.searchParams.set("window", normalizeEvidenceWindowPreset(state.profile?.evidenceWindow));
  url.searchParams.set("focus", String(normalizeTopFocus(state.profile?.focusCount)));
  if (state.activeView !== "overview") url.searchParams.set("view", state.activeView);
  if (state.selectedActorId) url.searchParams.set("actor", state.selectedActorId);
  if (state.selectedTechniqueId) url.searchParams.set("technique", state.selectedTechniqueId);
  return url;
}

function updateUrl(mode = "replace") {
  const method = mode === "push" ? "pushState" : "replaceState";
  history[method]({}, "", currentUrl());
}

function populateFilters() {
  elements.sector.innerHTML = state.intelligence.sectors
    .map((sector) => `<option value="${escapeHtml(sector)}">${escapeHtml(sector)}</option>`)
    .join("");
  elements.country.innerHTML = state.intelligence.countries
    .map((code) => ({ code, name: displayRegion(code) }))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(({ code, name }) => `<option value="${escapeHtml(code)}">${escapeHtml(name)}</option>`)
    .join("");

  const tactics = [...new Set(state.intelligence.techniques.flatMap((technique) => technique.tactics || []))]
    .sort((a, b) => a.localeCompare(b));
  elements.tacticFilter.innerHTML = '<option value="all">All tactics</option>' + tactics
    .map((tactic) => `<option value="${escapeHtml(tactic)}">${escapeHtml(tactic.replaceAll("-", " "))}</option>`)
    .join("");

  elements.sector.disabled = false;
  elements.country.disabled = false;
  elements.analyseButton.disabled = false;
}

function readProfileFromUrl() {
  const params = new URLSearchParams(location.search);
  const requestedSector = params.get("sector");
  const requestedCountry = params.get("country");
  const hasValidRequest = state.intelligence.sectors.includes(requestedSector) &&
    state.intelligence.countries.includes(requestedCountry);

  const sector = hasValidRequest
    ? requestedSector
    : state.intelligence.sectors.includes("Financial Services") ? "Financial Services" : state.intelligence.sectors[0];
  const country = hasValidRequest
    ? requestedCountry
    : state.intelligence.countries.includes("GB") ? "GB" : state.intelligence.countries[0];

  elements.organisation.value = "";
  elements.technology.value = "";
  elements.watchlist.value = "";
  elements.sector.value = sector;
  elements.country.value = country;
  elements.evidenceWindow.value = normalizeEvidenceWindowPreset(params.get("window") || params.get("lookback"));
  elements.focusCount.value = String(normalizeTopFocus(params.get("focus")));
  state.exampleProfile = !hasValidRequest;
  state.activeView = validViews.has(params.get("view")) ? params.get("view") : "overview";
  state.selectedActorId = params.get("actor");
  state.selectedTechniqueId = params.get("technique");
}

function renderHealth() {
  const reportHealth = (state.currentReportData?.sources || []).map((source) => ({
    ...source,
    sourceUrl: source.homepage || source.url,
    sourceVersion: "Dated public reporting",
  }));
  const health = [...(state.intelligence.health || []), ...reportHealth];
  const unknown = health.length < 7;
  const stale = health.some((source) => source.status !== "current");
  const status = unknown ? "unknown" : stale ? "stale" : "current";
  elements.healthDot.className = `status-dot ${status}`;
  elements.healthLabel.textContent = unknown ? "Source status unknown" : stale ? "Source warning" : "Sources current";
  elements.healthSummary.textContent = unknown
    ? "Source health metadata is incomplete."
    : stale
      ? `${health.filter((source) => source.status !== "current").length} source snapshot${health.filter((source) => source.status !== "current").length === 1 ? "" : "s"} using last-known-good data.`
      : `All ${health.length} source snapshots validated ${relativeAge(state.intelligence.generatedAt)}.`;
  elements.generatedAt.textContent = `Dataset built ${formatDate(state.intelligence.generatedAt, true)} (${relativeAge(state.intelligence.generatedAt)})`;

  elements.healthGrid.innerHTML = health.length ? health.map((source) => `
    <article class="health-card">
      <header>
        <h3>${escapeHtml(source.name)}</h3>
        <span class="badge ${escapeHtml(source.status)}">${escapeHtml(source.status)}</span>
      </header>
      <p>${source.status === "current" ? "Validated fresh retrieval" : "Validated last-known-good snapshot"}</p>
      <dl>
        <dt>Last success</dt><dd>${escapeHtml(formatDate(source.lastSuccessfulRefresh, true))}</dd>
        <dt>Records</dt><dd>${escapeHtml(source.recordCount ?? "Unknown")}</dd>
        <dt>Version</dt><dd>${escapeHtml(source.sourceVersion || "Not supplied")}</dd>
      </dl>
      ${source.error ? `<p>Refresh issue: ${escapeHtml(source.error)}</p>` : ""}
      <div class="link-row">${externalLink(source.sourceUrl, `Open ${source.name} source`)}</div>
    </article>
  `).join("") : '<div class="empty-state">Source health metadata is unavailable.</div>';

  const coverage = state.intelligence.coverage || {};
  elements.coverageGrid.innerHTML = [
    [coverage.actorsTotal ?? state.intelligence.actors.length, "ATT&CK actors"],
    [coverage.actorsWithProfileData ?? "—", "Actors with profile context"],
    [state.intelligence.techniques.length, "ATT&CK techniques"],
    [state.intelligence.vulnerabilities.length, "CISA KEV entries"],
    [state.currentReportData?.reports?.length ?? 0, "Automated public reports"],
  ].map(([value, label]) => `
    <article class="coverage-card"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></article>
  `).join("");
}

function fitBadge(actor) {
  return `<span class="badge ${fitBandClass(actor.fitBand)}">${escapeHtml(actor.fitBand)}</span>`;
}

function reportAuthorityLabel(report) {
  return {
    government: "Government reporting",
    "vendor-observed": "Vendor threat research",
  }[report.source?.authority] || "Public reporting";
}

function reportTypeLabel(report) {
  return {
    "campaign-report": "Campaign reporting",
    "actor-report": "Actor reporting",
    "malware-report": "Malware reporting",
    "security-advisory": "Security advisory",
  }[report.activityType] || "Public report";
}

function reportEntityNames(report) {
  return (report.entities || []).map((entity) => entity.name);
}

function reportEvidenceClass(report) {
  return report.evidenceClass === "direct-mention" || report.evidenceClass === "observed-context"
    ? "reviewed"
    : report.evidenceClass === "watchlist-mention" ? "warning" : "material";
}

function renderCurrentReports() {
  const label = evidenceWindowLabel();
  const total = state.reportEvidence?.all.length || 0;
  const excluded = state.reportEvidence?.excluded.length || 0;
  const summaries = state.currentReports.slice(0, 3);
  elements.currentReportCount.textContent = `${state.currentReports.length} matched report${state.currentReports.length === 1 ? "" : "s"} inside ${label}; ${excluded} matched report${excluded === 1 ? "" : "s"} outside the dated view. ${state.currentReportData.sources.length} feeds refresh automatically.`;

  elements.overviewReports.innerHTML = summaries.length ? summaries.map((report) => `
    <article class="signal-summary-item">
      <header><span class="badge ${reportEvidenceClass(report)}">${escapeHtml(report.evidenceLabel)}</span><span class="badge">${escapeHtml(formatDate(report.publishedAt))}</span></header>
      <h4>${escapeHtml(report.title)}</h4>
      <p>${escapeHtml(summarise(report.summary, 240) || "Open the source for full reporting and defensive guidance.")}</p>
      <a href="#activity" data-view-link="activity">${escapeHtml(report.source?.name || "Open evidence")}</a>
    </article>
  `).join("") : `<div class="empty-state">No credible report match falls inside ${escapeHtml(label)}. This means the automated feeds found no source text meeting the profile rules; it is not evidence that no threat exists. ${excluded || total} matched reports remain outside the selected window.</div>`;

  elements.currentReportList.innerHTML = state.currentReports.length ? state.currentReports.map((report) => `
    <article class="signal-card">
      <header>
        <div class="tag-row"><span class="badge current">${escapeHtml(reportTypeLabel(report))}</span><span class="badge">${escapeHtml(reportAuthorityLabel(report))}</span></div>
        <span class="badge ${reportEvidenceClass(report)}">${escapeHtml(report.evidenceLabel)}</span>
      </header>
      <h4>${escapeHtml(report.title)}</h4>
      <p>${escapeHtml(summarise(report.summary, 420) || "Open the source for the complete report.")}</p>
      ${reportEntityNames(report).length ? `<div class="tag-row">${reportEntityNames(report).map((name) => `<span class="badge">${escapeHtml(name)}</span>`).join("")}</div>` : ""}
      <p class="muted"><strong>Why included:</strong> ${escapeHtml(report.explanation)}</p>
      <footer><span>Published: ${escapeHtml(formatDate(report.publishedAt))}</span><span>Source: ${escapeHtml(report.source?.name || "Unknown")}</span></footer>
      <div class="link-row">${externalLink(report.url, "Open original report")}</div>
    </article>
  `).join("") : `<div class="empty-state">No automatically collected report meets this profile inside ${escapeHtml(label)}. Try a wider window, add an organisation or watchlist term, or inspect historical actor context.</div>`;
}

function renderJudgements() {
  const leaders = state.rankedActors.length
    ? state.rankedActors.filter((actor) => Math.abs(actor.profileFitExact - state.rankedActors[0].profileFitExact) < 1e-9)
    : [];
  const operational = state.techniques.filter((technique) => technique.operational);
  const detectionTechnique = operational.find((technique) => detectionsForTechnique(technique.id).length);
  const hasTechnology = Boolean(state.profile.technology.trim());
  const windowLabel = evidenceWindowLabel();
  const leadingReport = state.currentReports[0];
  const leadingEntity = state.currentEntities[0];

  const judgements = [
    {
      kind: "Recent reporting",
      badge: leadingReport ? leadingReport.evidenceLabel : "No dated match",
      badgeClass: leadingReport ? reportEvidenceClass(leadingReport) : "historical",
      title: leadingReport ? leadingReport.title : `No matched report inside ${windowLabel}`,
      body: leadingReport
        ? leadingReport.explanation
        : "The automated feeds found no report meeting the selected profile rules. This is not evidence that no threat exists.",
      foot: `${state.currentReports.length} matched report${state.currentReports.length === 1 ? "" : "s"} · ${state.reportEvidence?.excluded.length || 0} outside the window`,
      view: "activity",
    },
    {
      kind: "Named entities",
      badge: leadingEntity ? "Source-observed" : "None identified",
      badgeClass: leadingEntity ? "material" : "historical",
      title: leadingEntity ? leadingEntity.name : "No named actor or malware identified",
      body: leadingEntity
        ? `${leadingEntity.reportCount} matching report${leadingEntity.reportCount === 1 ? "" : "s"} across ${leadingEntity.sourceNames.length} source${leadingEntity.sourceNames.length === 1 ? "" : "s"}. Open the reports to assess the relationship.`
        : "Current reporting can still be relevant without naming a tracked threat actor or malware family.",
      foot: `${state.currentEntities.length} named entit${state.currentEntities.length === 1 ? "y" : "ies"} in the current result`,
      view: "activity",
    },
    {
      kind: "Defensive behaviour",
      badge: detectionTechnique ? "Reviewed KQL available" : "Telemetry mapping needed",
      badgeClass: detectionTechnique ? "reviewed" : "warning",
      title: detectionTechnique
        ? `${detectionTechnique.id} · ${detectionTechnique.name}`
        : operational[0] ? `${operational[0].id} · ${operational[0].name}` : "No operational technique available",
      body: detectionTechnique
        ? `${detectionTechnique.techniqueScore}/100 documentation-adjusted profile coverage with a Microsoft-schema-reviewed hunt starter.`
        : "Technique coverage is available, but reviewed Microsoft KQL is not yet mapped to the leading behaviour.",
      foot: `${operational.length} operational techniques`,
      view: "techniques",
    },
    {
      kind: "Exposure position",
      badge: hasTechnology ? "Possible keyword match" : "Exposure unknown",
      badgeClass: hasTechnology ? "possible" : "unknown",
      title: hasTechnology
        ? `${state.vulnerabilities.length} KEV keyword match${state.vulnerabilities.length === 1 ? "" : "es"}`
        : "No environment evidence supplied",
      body: hasTechnology
        ? "Keyword matching does not confirm vulnerable versions, internet exposure or asset ownership."
        : "CISA confirms exploitation globally; relevance requires technology or asset context.",
      foot: `${state.kevEvidence?.excluded.length || 0} KEV entries outside ${windowLabel}`,
      view: "vulnerabilities",
    },
  ];

  elements.judgementGrid.innerHTML = judgements.map((judgement) => `
    <article class="judgement-card">
      <div>
        <header>
          <span class="card-kicker">${escapeHtml(judgement.kind)}</span>
          <span class="badge ${escapeHtml(judgement.badgeClass)}">${escapeHtml(judgement.badge)}</span>
        </header>
        <h3>${escapeHtml(judgement.title)}</h3>
        <p>${escapeHtml(judgement.body)}</p>
      </div>
      <footer>
        <span>${escapeHtml(judgement.foot)}</span>
        <a href="#${escapeHtml(judgement.view)}" data-view-link="${escapeHtml(judgement.view)}">Inspect evidence</a>
      </footer>
    </article>
  `).join("");

  const firstActor = state.focusActors[0];
  const actions = [
    {
      title: leadingReport ? "Review the highest-relevance report" : "Broaden the profile or evidence window",
      detail: leadingReport ? `Open the original ${leadingReport.source?.name || "source"} report and verify what was observed, when and against whom.` : "Try a longer date window, organisation aliases, technologies or watchlist terms.",
      view: "activity",
    },
    {
      title: leadingEntity ? `Validate ${leadingEntity.name}` : "Review the historical actor context",
      detail: leadingEntity ? "Compare aliases and source claims before treating the entity as relevant to the organisation." : firstActor ? `Use ${firstActor.name} as background context, not a current targeting claim.` : "Broaden or change the profile context.",
      view: leadingEntity ? "activity" : "actors",
    },
    {
      title: detectionTechnique ? `Run a bounded ${detectionTechnique.id} hunt` : hasTechnology ? "Confirm KEV matches against asset evidence" : "Add technology context",
      detail: detectionTechnique ? "Check prerequisites, run with the documented lookback, review false positives and tune locally." : hasTechnology ? "Verify product, version and asset presence before prioritising remediation." : "Technology terms improve report matching and exposure triage.",
      view: detectionTechnique ? "techniques" : "vulnerabilities",
    },
  ];
  elements.priorityActions.innerHTML = actions.map((action) => `
    <li><div><strong>${escapeHtml(action.title)}</strong><span>${escapeHtml(action.detail)}</span></div><a href="#${escapeHtml(action.view)}" data-view-link="${escapeHtml(action.view)}">Open view</a></li>
  `).join("");
}

function renderOverview() {
  const actors = state.focusActors.slice(0, 5);
  const techniques = state.techniques.filter((technique) => technique.operational).slice(0, 5);
  const hasTechnology = Boolean(state.profile.technology.trim());
  const windowLabel = evidenceWindowLabel();

  elements.overviewScope.textContent = `${state.currentReports.length} matched public reports · ${focusLabel()} historical context · ${windowLabel}`;
  renderCurrentReports();
  elements.overviewActors.innerHTML = actors.length ? actors.map((actor) => `
    <div class="compact-item"><div><strong>${escapeHtml(actor.name)}</strong><span>#${actor.competitionRank} · ${escapeHtml(actor.fitBand)} · ${escapeHtml(actor.matchDimensions.join(" + "))}</span></div><b>${actor.profileFit}</b></div>
  `).join("") : '<div class="empty-state">No actor candidates match the selected context.</div>';
  elements.overviewTechniques.innerHTML = techniques.length ? techniques.map((technique) => `
    <div class="compact-item"><div><strong>${escapeHtml(technique.id)} · ${escapeHtml(technique.name)}</strong><span>${technique.actorCount} actors · ${detectionsForTechnique(technique.id).length ? "Reviewed KQL" : "No reviewed KQL"}</span></div><b>${technique.techniqueScore}</b></div>
  `).join("") : '<div class="empty-state">No operational techniques are mapped.</div>';
  elements.overviewCampaigns.innerHTML = `
    <div class="compact-item"><div><strong>${state.currentReports.filter((report) => report.activityType === "campaign-report").length} named campaign report${state.currentReports.filter((report) => report.activityType === "campaign-report").length === 1 ? "" : "s"}</strong><span>${state.campaigns.length} linked ATT&amp;CK campaigns remain available as historical context</span></div><b>${state.currentReports.filter((report) => report.activityType === "campaign-report").length}</b></div>
    <p class="muted">A report is labelled as campaign reporting only when its own source text describes a campaign or named operation.</p>
  `;
  elements.overviewExposure.innerHTML = `
    <div class="compact-item"><div><strong>${hasTechnology ? "Possible keyword matches" : "Exposure unknown"}</strong><span>${hasTechnology ? escapeHtml(state.profile.technology) : "No technology context supplied"}</span></div><b>${hasTechnology ? state.vulnerabilities.length : "—"}</b></div>
    <p class="muted">${state.vulnerabilities.length} KEV catalogue additions inside ${escapeHtml(windowLabel)}; ${state.kevEvidence.excluded.length} outside dated scope. A keyword match never confirms a vulnerable asset.</p>
  `;
  elements.overviewGaps.innerHTML = [
    "Actor rankings are based on historical public reporting and should be validated against current intelligence before operational use.",
    "Report publication dates show when evidence was published, not necessarily when the activity occurred.",
    "Infrastructure, domains, IP addresses, hashes and host/network artefacts are not collected.",
    hasTechnology ? "Technology matching is text-based and does not include product versions or asset exposure." : "No technology or asset context is available for KEV relevance.",
    "Microsoft KQL is schema reviewed but has not been validated against this organisation's tenant or baselines.",
  ].map((gap) => `<li>${escapeHtml(gap)}</li>`).join("");
}

function filteredActors() {
  const query = elements.actorSearch.value.trim().toLowerCase();
  const band = elements.actorBandFilter.value;
  return state.rankedActors.filter((actor) => {
    const haystack = `${actor.id} ${actor.name} ${(actor.aliases || []).join(" ")}`.toLowerCase();
    return (!query || haystack.includes(query)) && (band === "all" || actor.fitBand === band);
  });
}

function actorRow(actor) {
  const selected = state.selectedActorId === actor.id;
  const inFocus = state.focusActors.some((entry) => entry.id === actor.id);
  return `
    <button class="actor-row" type="button" data-actor-id="${escapeHtml(actor.id)}" aria-pressed="${selected}">
      <span>
        <span class="row-title"><strong>${escapeHtml(actor.name)}</strong>${fitBadge(actor)}${inFocus ? '<span class="badge reviewed">In analysis focus</span>' : '<span class="badge historical">Outside analysis focus</span>'}</span>
        <span class="row-meta"><span>${escapeHtml(actor.id)}</span><span>Rank #${actor.competitionRank}</span><span>${escapeHtml(actor.matchDimensions.join(" + "))}</span><span>${actor.campaigns?.length || 0} campaigns</span><span>${actor.techniques?.length || 0} techniques</span></span>
      </span>
      <span class="row-score"><strong>${actor.profileFit}</strong><span>profile fit / 100</span></span>
    </button>`;
}

function renderActors() {
  const actors = filteredActors();
  const visible = actors.slice(0, state.actorVisible);
  elements.actorCount.textContent = `Showing ${visible.length} of ${actors.length} filtered actors. ${state.focusSelection.actualCount} contribute to ${focusLabel()}; ${state.rankedActors.length} total profile matches remain inspectable.`;
  elements.actorList.innerHTML = visible.length ? visible.map(actorRow).join("") : '<div class="empty-state">No actors match these filters. Clear the filters or change the profile context.</div>';
  elements.actorMore.hidden = visible.length >= actors.length;
  elements.actorMore.textContent = `Show ${Math.min(10, actors.length - visible.length)} more actors`;
  renderActorDetail();
  renderCampaigns();
}

function renderActorDetail() {
  const actor = state.rankedActors.find((entry) => entry.id === state.selectedActorId);
  if (!actor) {
    elements.actorDetail.innerHTML = '<div class="empty-state">Select an actor to inspect its evidence, campaigns, techniques and analytical gaps.</div>';
    return;
  }

  const evidence = actor.targetingEvidence;
  const inFocus = state.focusActors.some((entry) => entry.id === actor.id);
  const allLinkedCampaigns = state.campaignEvidence.all.filter((campaign) => campaign.actorIds.includes(actor.id));
  const linkedCampaigns = allLinkedCampaigns.filter((campaign) => campaign.evidenceWindow.status === "in-window");
  const actorTechniques = state.techniques.filter((technique) => technique.actorIds.includes(actor.id)).slice(0, 12);
  elements.actorDetail.innerHTML = `
    <div class="detail-header">
      <div><span class="card-kicker">Actor evidence</span><h3>${escapeHtml(actor.name)}</h3><div class="tag-row">${fitBadge(actor)}<span class="badge ${inFocus ? "reviewed" : "historical"}">${inFocus ? `Contributes to ${escapeHtml(focusLabel())}` : `Outside ${escapeHtml(focusLabel())}`}</span><span class="badge">Historical public-source evidence</span><span class="badge">${escapeHtml(actor.id)}</span></div></div>
      <span class="row-score"><strong>${actor.profileFit}</strong><span>profile fit</span></span>
    </div>
    <p class="muted">${escapeHtml(actor.description || "ATT&CK actor record.")}</p>
    <div class="detail-section">
      <h4>Score breakdown</h4>
      <div class="score-breakdown">
        <div class="score-component"><strong>${actor.scoreComponents.sector.points}</strong><span>Sector points · ${actor.scoreComponents.sector.actorBreadth} of ${actor.scoreComponents.sector.universe} sectors recorded</span></div>
        <div class="score-component"><strong>${actor.scoreComponents.country.points}</strong><span>Country points · ${actor.scoreComponents.country.actorBreadth} of ${actor.scoreComponents.country.universe} countries recorded</span></div>
      </div>
      <p>Specificity rewards narrow context. It does not estimate attack probability or business impact.</p>
    </div>
    <div class="detail-section">
      <h4>Targeting evidence</h4>
      <ul>
        ${actor.sectorMatch ? `<li>Recorded sector context includes ${escapeHtml(state.profile.sector)}.</li>` : ""}
        ${actor.countryMatch ? `<li>Recorded country context includes ${escapeHtml(displayRegion(state.profile.country))}.</li>` : ""}
        <li>Sector and country are independent aggregate attributes; joint targeting evidence is not available.</li>
        <li>Observation date is unavailable. Profile inference confidence remains low.</li>
      </ul>
      ${evidence?.description ? `<p>${escapeHtml(evidence.description)}</p>` : ""}
      <div class="link-row">${sourceLinks(evidence?.references, "Open targeting reference")}</div>
    </div>
    <div class="detail-section">
      <h4>Linked context</h4>
      <p>${linkedCampaigns.length} ATT&amp;CK campaigns inside ${escapeHtml(evidenceWindowLabel())} · ${allLinkedCampaigns.length - linkedCampaigns.length} older or undated · ${actorTechniques.length} prioritised techniques shown · ${actor.software?.length || 0} software relationships.</p>
      ${inFocus ? "" : `<p class="muted">This actor remains available for inspection and in the complete candidate export, but it does not contribute to downstream techniques, campaigns, software or KQL priorities under the current ${escapeHtml(focusLabel())} scope.</p>`}
      <div class="tag-row">${actorTechniques.slice(0, 8).map((technique) => `<button class="quiet-button" type="button" data-technique-id="${escapeHtml(technique.id)}">${escapeHtml(technique.id)}</button>`).join("")}</div>
    </div>
    <div class="detail-section">
      <h4>Analytical gaps</h4>
      <ul><li>No dated assertion tying this actor to the selected sector in the selected country.</li><li>No organisation-specific victim evidence.</li><li>No infrastructure or indicator lifecycle data in the current source set.</li></ul>
    </div>
  `;
}

function campaignRecency(campaign) {
  if (campaign.ageDays === null) return { label: "Activity date unavailable", className: "unknown" };
  if (campaign.ageDays <= 180) return { label: "Last seen within 6 months", className: "current" };
  if (campaign.evidenceWindow?.status === "in-window") return { label: `Inside ${evidenceWindowLabel()}`, className: "material" };
  return { label: `Outside ${evidenceWindowLabel()}`, className: "historical" };
}

function renderCampaigns() {
  const selectedActor = state.selectedActorId;
  const allCampaigns = selectedActor
    ? state.campaignEvidence.all.filter((campaign) => campaign.actorIds.includes(selectedActor))
    : state.campaignEvidence.all;
  const campaigns = allCampaigns.filter((campaign) => campaign.evidenceWindow.status === "in-window");
  const excludedCount = allCampaigns.length - campaigns.length;
  elements.campaignCount.textContent = selectedActor
    ? `${campaigns.length} inside ${evidenceWindowLabel()}; ${excludedCount} older, undated or excluded for the selected actor`
    : `${campaigns.length} inside ${evidenceWindowLabel()}; ${excludedCount} older, undated or excluded for ${focusLabel()}`;
  elements.campaignList.innerHTML = campaigns.length ? campaigns.map((campaign) => {
    const recency = campaignRecency(campaign);
    const linkedNames = campaign.actorIds.map((id) => state.rankedActors.find((actor) => actor.id === id)?.name).filter(Boolean);
    return `
      <article class="campaign-card">
        <div class="tag-row"><span class="badge ${recency.className}">${escapeHtml(recency.label)}</span><span class="badge">${escapeHtml(campaign.id)}</span></div>
        <h3>${escapeHtml(campaign.name)}</h3>
        <p>${escapeHtml(campaign.description || "ATT&CK campaign record.")}</p>
        <footer><span>Last seen: ${escapeHtml(formatDate(campaign.lastSeen))}</span><span>Record updated: ${escapeHtml(formatDate(campaign.modified))}</span><span>Linked actors: ${escapeHtml(linkedNames.join(", ") || "Not named")}</span></footer>
        <div class="link-row">${sourceLinks(campaign.references, "Open campaign source")}</div>
      </article>`;
  }).join("") : `<div class="empty-state">No linked ATT&amp;CK campaign has a valid <code>last_seen</code> inside ${escapeHtml(evidenceWindowLabel())}. ${excludedCount ? `${excludedCount} linked record${excludedCount === 1 ? " is" : "s are"} retained outside the dated view and in the complete JSON export.` : "No linked campaign record exists for this analytical focus."}</div>`;
}

function filteredTechniques() {
  const query = elements.techniqueSearch.value.trim().toLowerCase();
  const tactic = elements.tacticFilter.value;
  const detectionOnly = elements.detectionFilter.checked;
  return state.techniques.filter((technique) => {
    const haystack = `${technique.id} ${technique.name}`.toLowerCase();
    return (!query || haystack.includes(query)) &&
      (tactic === "all" || technique.tactics?.includes(tactic)) &&
      (!detectionOnly || detectionsForTechnique(technique.id).length);
  });
}

function techniqueRow(technique) {
  const selected = state.selectedTechniqueId === technique.id;
  const detections = detectionsForTechnique(technique.id);
  return `
    <button class="technique-row" type="button" data-technique-id="${escapeHtml(technique.id)}" aria-pressed="${selected}">
      <span>
        <span class="row-title"><strong>${escapeHtml(technique.id)} · ${escapeHtml(technique.name || "Unknown technique")}</strong>${detections.length ? '<span class="badge reviewed">Reviewed KQL</span>' : '<span class="badge">Telemetry mapping only</span>'}</span>
        <span class="row-meta"><span>${technique.actorCount} actors in analysis focus</span><span>${technique.focusedActorCount} highest-fit-band actors</span><span>${escapeHtml((technique.tactics || []).join(", ") || "No tactic")}</span></span>
      </span>
      <span class="row-score"><strong>${technique.techniqueScore}</strong><span>coverage / 100</span></span>
    </button>`;
}

function renderTechniques() {
  const techniques = filteredTechniques();
  const visible = techniques.slice(0, state.techniqueVisible);
  elements.techniqueCount.textContent = `Showing ${visible.length} of ${techniques.length} filtered techniques (${state.techniques.length} total). Mapping completeness: ${state.techniques[0]?.mappingCompleteness || 0}%.`;
  elements.techniqueList.innerHTML = visible.length ? visible.map(techniqueRow).join("") : '<div class="empty-state">No techniques match these filters. Clear the filters to restore the full result.</div>';
  elements.techniqueMore.hidden = visible.length >= techniques.length;
  elements.techniqueMore.textContent = `Show ${Math.min(20, techniques.length - visible.length)} more techniques`;
  renderTechniqueDetail();
}

function detectionCard(detection) {
  return `
    <article class="detection-card">
      <div class="detection-meta"><span class="badge reviewed">${escapeHtml(detection.type)}</span><span class="badge warning">Tenant validation required</span></div>
      <h4>${escapeHtml(detection.title)}</h4>
      <p>${escapeHtml(detection.purpose)}</p>
      <div class="detail-section">
        <h4>Execution context</h4>
        <ul><li>Run in: ${escapeHtml(detection.targetProduct)}</li><li>Lookback: ${escapeHtml(detection.lookback)}</li><li>Tables: ${escapeHtml(detection.tables.join(", "))}</li><li>${escapeHtml(detection.nrtCompatibility)}</li></ul>
      </div>
      <details><summary>Prerequisites, false positives and tuning</summary>
        <div class="detail-section"><h4>Prerequisites</h4><ul>${detection.prerequisites.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
        <div class="detail-section"><h4>Likely false positives</h4><ul>${detection.falsePositives.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
        <div class="detail-section"><h4>Tuning</h4><ul>${detection.tuning.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
      </details>
      <details><summary>Bounded validation procedure</summary><ol>${detection.validationSteps.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol></details>
      <div class="kql-block"><button class="copy-button" type="button" data-copy-detection="${escapeHtml(detection.id)}">Copy KQL</button><pre><code>${escapeHtml(detection.kql)}</code></pre></div>
      <div class="detail-section"><h4>Official Microsoft schema</h4><p>Schema reviewed ${escapeHtml(formatDate(detection.schemaVerifiedAt))}. Successful schema review does not replace tenant testing.</p><div class="link-row">${detection.documentationLinks.map((link) => externalLink(link.url, link.label)).join("")}</div></div>
    </article>`;
}

function renderTechniqueDetail() {
  const technique = state.techniques.find((entry) => entry.id === state.selectedTechniqueId);
  if (!technique) {
    elements.techniqueDetail.innerHTML = '<div class="empty-state">Select a technique to inspect contributing actors, telemetry requirements and reviewed hunt content.</div>';
    return;
  }
  const detections = detectionsForTechnique(technique.id);
  const actors = technique.actorIds
    .map((id) => state.rankedActors.find((actor) => actor.id === id))
    .filter(Boolean)
    .sort((a, b) => b.profileFitExact - a.profileFitExact)
    .slice(0, 10);

  elements.techniqueDetail.innerHTML = `
    <div class="detail-header"><div><span class="card-kicker">Technique evidence</span><h3>${escapeHtml(technique.id)} · ${escapeHtml(technique.name)}</h3><div class="tag-row"><span class="badge">${escapeHtml((technique.tactics || []).join(", ") || "No tactic")}</span>${detections.length ? '<span class="badge reviewed">Reviewed KQL</span>' : ""}</div></div><span class="row-score"><strong>${technique.techniqueScore}</strong><span>coverage</span></span></div>
    <p class="muted">${escapeHtml(technique.description || "ATT&CK technique record.")}</p>
    <div class="detail-section"><h4>Why it is prioritised</h4><ul><li>${technique.actorCount} profile-matched actors contribute.</li><li>Weighted coverage: ${technique.weightedCoverage}%.</li><li>Documentation-adjusted coverage: ${technique.documentationAdjustedCoverage}%.</li><li>The conservative score uses the lower coverage value to reduce documentation bias.</li></ul></div>
    <div class="detail-section"><h4>Contributing actors</h4><div class="tag-row">${actors.map((actor) => `<button class="quiet-button" type="button" data-actor-id="${escapeHtml(actor.id)}">${escapeHtml(actor.name)} · ${actor.profileFit}</button>`).join("")}</div></div>
    <div class="detail-section"><h4>ATT&amp;CK context</h4><p>Platforms: ${escapeHtml((technique.platforms || []).join(", ") || "Not supplied")}</p><div class="link-row"><a href="${escapeHtml(attackTechniqueUrl(technique.id))}" target="_blank" rel="noopener noreferrer">Open ${escapeHtml(technique.id)} in MITRE ATT&amp;CK</a></div></div>
    <div class="detail-section"><h4>Detection content</h4>${detections.length ? detections.map(detectionCard).join("") : '<div class="empty-state">No Microsoft-schema-reviewed KQL is available for this technique. Confirm ATT&amp;CK data sources and tenant telemetry before authoring a hunt.</div>'}</div>
  `;
}

function renderVulnerabilities() {
  const hasTechnology = Boolean(state.profile.technology.trim());
  const visible = state.vulnerabilities.slice(0, state.kevVisible);
  elements.kevContext.textContent = hasTechnology
    ? `Possible text matches for: ${state.profile.technology}. Showing catalogue additions inside ${evidenceWindowLabel()}; product version and exposure remain unconfirmed.`
    : `Global exploitation watchlist added to KEV inside ${evidenceWindowLabel()}. No environment evidence has been supplied.`;
  elements.exposureBanner.innerHTML = `
    <span class="badge ${hasTechnology ? "possible" : "unknown"}">${hasTechnology ? "Possible match" : "Exposure unknown"}</span>
    <div><strong>${hasTechnology ? "Keyword context only" : "No technology or inventory context"}</strong><span>${hasTechnology ? "Verify vendor, product, version, asset ownership, criticality and internet exposure before assigning priority." : "CISA KEV confirms exploitation in the wild, but does not establish relevance to this environment."}</span></div>`;
  elements.kevCount.textContent = `Showing ${visible.length} of ${state.vulnerabilities.length} ${hasTechnology ? "possible keyword matches" : "global KEV entries"} inside ${evidenceWindowLabel()}; ${state.kevEvidence.excluded.length} entries are outside the dated scope.`;
  elements.kevList.innerHTML = visible.length ? visible.map((entry) => `
    <article class="kev-card">
      <div class="tag-row"><span class="badge ${entry.environmentMatch}">${entry.environmentMatch === "possible" ? "Possible keyword match" : "Exposure unknown"}</span><span class="badge danger">Known exploited</span>${String(entry.ransomware).toLowerCase() === "known" ? '<span class="badge warning">Known ransomware use</span>' : ""}</div>
      <h3>${escapeHtml(entry.cve)} · ${escapeHtml(entry.vendor)} ${escapeHtml(entry.product)}</h3>
      <p>${escapeHtml(entry.description || entry.name)}</p>
      <details><summary>Remediation and evidence context</summary><ul class="plain-list"><li>KEV added: ${escapeHtml(formatDate(entry.dateAdded))}.</li><li>CISA FCEB remediation due date: ${escapeHtml(formatDate(entry.dueDate))}.</li><li>Required action: ${escapeHtml(entry.action || "Review CISA guidance.")}</li><li>Exposure is not confirmed by this workbench.</li></ul></details>
      <footer><span>${escapeHtml(entry.name)}</span>${entry.matchedTerms?.length ? `<span>Matched: ${escapeHtml(entry.matchedTerms.join(", "))}</span>` : ""}</footer>
      <div class="link-row"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">Open CISA KEV catalog</a>${sourceLinks(entry.references, "Open remediation reference")}</div>
    </article>`).join("") : `<div class="empty-state">No KEV catalogue addition matches this context inside ${escapeHtml(evidenceWindowLabel())}. ${state.kevEvidence.excluded.length ? `${state.kevEvidence.excluded.length} older, undated or excluded record${state.kevEvidence.excluded.length === 1 ? " is" : "s are"} retained in the complete export.` : "This does not confirm that the environment is not exposed."}</div>`;
  elements.kevMore.hidden = visible.length >= state.vulnerabilities.length;
  elements.kevMore.textContent = `Show ${Math.min(12, state.vulnerabilities.length - visible.length)} more KEV entries`;
}

function renderModelSelector() {
  const selected = state.focusActors.some((actor) => actor.id === state.selectedActorId) ? state.selectedActorId : "";
  elements.modelActorSelect.innerHTML = `<option value="">Choose an actor from ${escapeHtml(focusLabel())}—no automatic tie-break</option>` + state.focusActors
    .map((actor) => `<option value="${escapeHtml(actor.id)}" ${actor.id === selected ? "selected" : ""}>#${actor.competitionRank} ${escapeHtml(actor.name)} · ${actor.profileFit}</option>`)
    .join("");
}

function renderModels() {
  renderModelSelector();
  const actor = state.focusActors.find((entry) => entry.id === state.selectedActorId);
  if (!actor) {
    const leaders = state.rankedActors.filter((entry) => state.rankedActors[0] && Math.abs(entry.profileFitExact - state.rankedActors[0].profileFitExact) < 1e-9);
    elements.diamondView.innerHTML = `<div class="empty-state">Select an actor to build a partial relationship frame. ${leaders.length > 1 ? `${leaders.length} actors share the leading score, so none is selected automatically.` : "No actor is selected automatically."}</div>`;
    elements.pyramidView.innerHTML = '<div class="empty-state">Select an actor to inspect actor-scoped collection coverage, or use the profile-level technique view.</div>';
    return;
  }

  const actorTechniqueIds = new Set(actor.techniques || []);
  const actorTechniques = state.techniques.filter((technique) => actorTechniqueIds.has(technique.id)).slice(0, 4);
  const softwareById = new Map(state.intelligence.software.map((entry) => [entry.id, entry]));
  const actorSoftware = (actor.software || []).map((id) => softwareById.get(id)).filter(Boolean).slice(0, 4);
  elements.diamondView.innerHTML = `
    <div class="diamond-layout">
      <article class="diamond-node diamond-adversary"><strong>Adversary · source-linked</strong><h3>${escapeHtml(actor.name)}</h3><p>${escapeHtml(actor.id)} · ${actor.profileFit}/100 profile fit</p></article>
      <article class="diamond-node diamond-capability"><strong>Capability · ATT&amp;CK relationship</strong><p>${actorTechniques.map((technique) => `${escapeHtml(technique.id)} ${escapeHtml(technique.name)}`).join(" · ") || "No techniques mapped"}</p>${actorSoftware.length ? `<p>Software: ${actorSoftware.map((entry) => escapeHtml(entry.name)).join(", ")}</p>` : ""}</article>
      <div class="diamond-centre"><div><span class="badge warning">Partial frame</span><p>Actor-to-capability evidence only</p></div></div>
      <article class="diamond-node diamond-infrastructure"><strong>Infrastructure · not collected</strong><h3>Evidence unavailable</h3><p>No domains, IP addresses or infrastructure relationships are inferred.</p></article>
      <article class="diamond-node diamond-victim"><strong>Victim · profile context only</strong><h3>${escapeHtml(state.profile.sector)}</h3><p>${escapeHtml(displayRegion(state.profile.country))} · no direct victim assertion</p></article>
    </div>
    <div class="model-alternative"><strong>Text alternative:</strong> ATT&amp;CK links ${escapeHtml(actor.name)} to ${actorTechniques.length} leading capabilities shown above. The selected sector and country are separate profile context. Infrastructure and direct victim evidence are not collected, so this is not a complete Diamond event.</div>`;

  const tiers = [
    ["TTPs", `${actor.techniques?.length || 0} ATT&CK techniques mapped`, "Collected", "reviewed"],
    ["Tools / malware", `${actor.software?.length || 0} ATT&CK software relationships`, "Collected", "reviewed"],
    ["Host / network artefacts", "No lifecycle-controlled source", "Not collected", "unknown"],
    ["Domains", "No lifecycle-controlled source", "Not collected", "unknown"],
    ["IP addresses", "No lifecycle-controlled source", "Not collected", "unknown"],
    ["Hashes", "No lifecycle-controlled source", "Not collected", "unknown"],
  ];
  elements.pyramidView.innerHTML = `<div class="pyramid-table">${tiers.map(([name, detail, status, className]) => `
    <div class="pyramid-tier"><strong>${escapeHtml(name)}</strong><span>${escapeHtml(detail)}</span><span class="badge ${escapeHtml(className)}">${escapeHtml(status)}</span></div>`).join("")}</div>
    <div class="model-alternative"><strong>Interpretation:</strong> behaviour and tool relationships support durable hunting hypotheses. Missing lower-layer indicators mean they are not collected here—not that none exist.</div>`;
}

function renderProfileHeader() {
  elements.profileMode.textContent = state.exampleProfile ? "Example context" : "Current context";
  elements.scopeBadge.textContent = state.profile.organisation ? "Organisation terms matched locally" : "OSINT profile relevance";
  elements.windowBadge.textContent = `Evidence: ${evidenceWindowLabel()}`;
  elements.focusBadge.textContent = `Focus: ${focusLabel()}`;
  elements.profileTitle.textContent = profileName();
  elements.profileDate.textContent = `Built from source snapshots ${formatDate(state.intelligence.generatedAt, true)}`;
  const basis = state.profile.organisation
    ? `${state.profile.sector} + ${displayRegion(state.profile.country)} with private organisation terms. A report mention does not prove compromise or deliberate targeting.`
    : `${state.profile.sector} + ${displayRegion(state.profile.country)}. Current reports require sector relevance; country-only mentions are excluded.`;
  elements.profileBasis.textContent = `${basis} ${focusLabel()} supplies historical background; ${evidenceWindowLabel()} applies only to genuinely dated evidence.`;
}

function renderPrintReport() {
  const leaders = state.rankedActors.filter((actor) =>
    state.rankedActors[0] && Math.abs(actor.profileFitExact - state.rankedActors[0].profileFitExact) < 1e-9);
  const operationalTechniques = state.techniques.filter((technique) => technique.operational);
  const reportTechniques = operationalTechniques.slice(0, 10);
  const reportActors = state.focusActors;
  const reportReports = state.currentReports.slice(0, 8);
  const reportCampaigns = state.campaigns.slice(0, 6);
  const reportVulnerabilities = state.vulnerabilities.slice(0, 10);
  const hunts = [];
  const seenHunts = new Set();
  for (const technique of operationalTechniques) {
    for (const detection of detectionsForTechnique(technique.id)) {
      if (seenHunts.has(detection.id)) continue;
      seenHunts.add(detection.id);
      hunts.push({ detection, technique });
      if (hunts.length === 5) break;
    }
    if (hunts.length === 5) break;
  }

  const technologyContext = state.profile.technology || "Not supplied";
  const reportCreatedAt = new Date();
  const exposureSummary = state.profile.technology
    ? `${state.vulnerabilities.length} CISA KEV catalogue additions inside ${evidenceWindowLabel()} have a possible text match to the supplied technology context. Asset presence and exposure remain unconfirmed.`
    : `No technology context was supplied. ${state.vulnerabilities.length} CISA KEV catalogue additions fall inside ${evidenceWindowLabel()}; environment exposure is unknown.`;
  const leaderSummary = leaders.length > 1
    ? `${leaders.length} actors share the leading profile-fit score of ${leaders[0].profileFit}/100.`
    : leaders[0]
      ? `${leaders[0].name} is the leading profile match at ${leaders[0].profileFit}/100.`
      : "No actor in the current targeting source matches this context.";

  elements.reportContent.innerHTML = `
    <header class="report-header">
      <div><p class="report-kicker">Threat Profile Workbench</p><h1>${escapeHtml(profileName())}</h1><p>Evidence-led cyber threat intelligence decision report</p></div>
      <dl><dt>Report created</dt><dd>${escapeHtml(formatDate(reportCreatedAt, true))}</dd><dt>Intelligence snapshot</dt><dd>${escapeHtml(formatDate(state.intelligence.generatedAt, true))}</dd><dt>Assessment type</dt><dd>Profile relevance inference</dd></dl>
    </header>

    <section class="report-section">
      <h2>Executive summary</h2>
      <div class="report-summary-grid">
        <article><strong>Actor landscape</strong><p>${escapeHtml(leaderSummary)} Profile fit is relevance, not likelihood; validate it against current intelligence before operational use.</p></article>
        <article><strong>Defensive behaviour</strong><p>${reportTechniques.length ? `${reportTechniques.length} leading operational techniques are included below; ${hunts.length} have mapped Microsoft-schema-reviewed hunting starters in this report.` : "No operational ATT&CK techniques are available for this context."}</p></article>
        <article><strong>Recent reporting</strong><p>${state.currentReports.length} automatically collected public reports match the profile inside ${escapeHtml(evidenceWindowLabel())}; ${state.currentEntities.length} named actors or malware families were identified. Publication dates provide recency context, not proof of current activity.</p></article>
        <article><strong>Exposure context</strong><p>${escapeHtml(exposureSummary)}</p></article>
      </div>
    </section>

    <section class="report-section report-context">
      <h2>Assessment context</h2>
      <dl><dt>Organisation / brands</dt><dd>${escapeHtml(state.profile.organisation || "Not supplied")}${state.profile.organisation ? " — matched privately in this browser" : ""}</dd><dt>Sector</dt><dd>${escapeHtml(state.profile.sector)}</dd><dt>Country</dt><dd>${escapeHtml(displayRegion(state.profile.country))}</dd><dt>Technology context</dt><dd>${escapeHtml(technologyContext)}</dd><dt>Actor watchlist</dt><dd>${escapeHtml(state.profile.watchlist || "Not supplied")}</dd><dt>Analysis focus</dt><dd>${escapeHtml(focusLabel())} (${state.focusSelection.actualCount} historical actors included)</dd><dt>Dated evidence window</dt><dd>${escapeHtml(evidenceWindowLabel())} · ${state.campaignEvidence.window.cutoff ? `cutoff ${escapeHtml(formatDate(state.campaignEvidence.window.cutoff))}` : "no lower date limit"} · as of ${escapeHtml(formatDate(state.campaignEvidence.window.asOf))}</dd></dl>
    </section>

    <section class="report-section">
      <h2>Matched public reporting</h2>
      ${reportReports.length ? `<table><thead><tr><th>Report</th><th>Source</th><th>Published</th><th>Why included</th></tr></thead><tbody>${reportReports.map((report) => `<tr><td>${escapeHtml(report.title)}${reportEntityNames(report).length ? `<br><small>${escapeHtml(reportEntityNames(report).join(", "))}</small>` : ""}</td><td>${escapeHtml(report.source?.name || "Unknown")}</td><td>${escapeHtml(formatDate(report.publishedAt))}</td><td>${escapeHtml(report.evidenceLabel)} — ${escapeHtml(report.explanation)}</td></tr>`).join("")}</tbody></table>` : `<p>No automatically collected report meets this profile inside ${escapeHtml(evidenceWindowLabel())}.</p>`}
      <p class="report-note">Reports are matched from their own title and summary. Country-only mentions never create sector relevance. A name mention is not proof of compromise, deliberate targeting or attribution.</p>
    </section>

    <section class="report-section">
      <h2>Priority actions</h2>
      <ol>
        <li><strong>Review the original current reports.</strong> Confirm what was observed, when it occurred and whether the affected victims resemble the organisation.</li>
        <li><strong>Run a bounded hunt.</strong> Confirm prerequisites, use the documented lookback, review false positives and tune locally before promotion.</li>
        <li><strong>Confirm exposure with asset evidence.</strong> Treat KEV keyword matches as triage leads until product presence, affected versions and remediation state are verified.</li>
        <li><strong>Record the evidence gaps.</strong> This source set does not collect infrastructure, indicators or organisation-specific victim observations.</li>
      </ol>
    </section>

    <section class="report-section report-page-break">
      <h2>${escapeHtml(focusLabel())} actor candidates</h2>
      ${reportActors.length ? `<table><thead><tr><th>Rank</th><th>Actor</th><th>Profile fit</th><th>Match basis</th><th>Confidence</th></tr></thead><tbody>${reportActors.map((actor) => `<tr><td>${actor.competitionRank}</td><td>${escapeHtml(actor.name)}<br><small>${escapeHtml(actor.id)}</small></td><td>${actor.profileFit}/100<br><small>${escapeHtml(actor.fitBand)}</small></td><td>${escapeHtml(actor.matchDimensions.join(" + "))}</td><td>${escapeHtml(actor.analyticConfidence)}</td></tr>`).join("")}</tbody></table>` : "<p>No matching actors.</p>"}
      <p class="report-note">Sector and country are independent historical attributes. A match does not prove a joint targeting event or direct targeting of the named organisation.</p>
    </section>

    <section class="report-section">
      <h2>Priority operational techniques</h2>
      ${reportTechniques.length ? `<table><thead><tr><th>Technique</th><th>Tactic</th><th>Coverage</th><th>Actors</th><th>Reviewed KQL</th></tr></thead><tbody>${reportTechniques.map((technique) => `<tr><td>${escapeHtml(technique.id)}<br><small>${escapeHtml(technique.name)}</small></td><td>${escapeHtml((technique.tactics || []).join(", ") || "Not supplied")}</td><td>${technique.techniqueScore}/100</td><td>${technique.actorCount}</td><td>${detectionsForTechnique(technique.id).length ? "Available" : "Not mapped"}</td></tr>`).join("")}</tbody></table>` : "<p>No operational techniques mapped.</p>"}
      <p class="report-note">Coverage is the lower of profile-fit-weighted and documentation-adjusted actor coverage. It is not detection efficacy or observed activity.</p>
    </section>

    <section class="report-section">
      <h2>Recommended Microsoft hunts</h2>
      ${hunts.length ? `<div class="report-hunts">${hunts.map(({ detection, technique }) => `<article><strong>${escapeHtml(detection.title)}</strong><p>${escapeHtml(technique.id)} · ${escapeHtml(detection.targetProduct)}</p><p>Tables: ${escapeHtml(detection.tables.join(", "))} · Lookback: ${escapeHtml(detection.lookback)}</p><p>${escapeHtml(detection.status)} · Schema reviewed ${escapeHtml(formatDate(detection.schemaVerifiedAt))}</p></article>`).join("")}</div>` : "<p>No reviewed hunting starter is mapped to the leading operational techniques.</p>"}
      <p class="report-note">Review prerequisites, official Microsoft documentation, false positives and validation steps in the interactive workbench before running or scheduling a query.</p>
    </section>

    <section class="report-section report-page-break">
      <h2>Campaign context</h2>
      ${reportCampaigns.length ? `<table><thead><tr><th>Campaign</th><th>Last seen</th><th>Linked actors</th><th>Profile fit</th></tr></thead><tbody>${reportCampaigns.map((campaign) => `<tr><td>${escapeHtml(campaign.name)}<br><small>${escapeHtml(campaign.id)}</small></td><td>${escapeHtml(formatDate(campaign.lastSeen))}</td><td>${escapeHtml((campaign.actorIds || []).length)}</td><td>${campaign.campaignProfileFit}/100</td></tr>`).join("")}</tbody></table>` : `<p>No linked ATT&amp;CK campaign has a valid <code>last_seen</code> inside ${escapeHtml(evidenceWindowLabel())}.</p>`}
      <p class="report-note">${state.campaignEvidence.excluded.length} linked campaign records are older, undated, invalid or future-dated and remain available in the complete JSON export.</p>
    </section>

    <section class="report-section">
      <h2>KEV exposure context</h2>
      <p>${escapeHtml(exposureSummary)}</p>
      ${state.profile.technology && reportVulnerabilities.length ? `<table><thead><tr><th>CVE</th><th>Vendor / product</th><th>Added to KEV</th><th>Ransomware use</th></tr></thead><tbody>${reportVulnerabilities.map((entry) => `<tr><td>${escapeHtml(entry.cve)}</td><td>${escapeHtml(entry.vendor)} ${escapeHtml(entry.product)}</td><td>${escapeHtml(formatDate(entry.dateAdded))}</td><td>${escapeHtml(entry.ransomware)}</td></tr>`).join("")}</tbody></table>` : ""}
      <p class="report-note">The evidence window uses CISA <code>dateAdded</code>, which is a catalogue-addition date—not an exploitation date. ${state.kevEvidence.excluded.length} records are outside the selected dated scope. This workbench has no asset inventory or vulnerability scan and therefore cannot confirm exposure.</p>
    </section>

    <section class="report-section">
      <h2>Sources and evidence boundaries</h2>
      <div class="report-sources">${[...(state.intelligence.health || []), ...(state.currentReportData.sources || []).map((source) => ({ ...source, sourceUrl: source.homepage || source.url, sourceVersion: "Dated public reporting" }))].map((source) => `<article><strong>${escapeHtml(source.name)}</strong><p>Status: ${escapeHtml(source.status)} · Records: ${escapeHtml(source.recordCount ?? "Unknown")} · Version: ${escapeHtml(source.sourceVersion || "Not supplied")} · Last success: ${escapeHtml(formatDate(source.lastSuccessfulRefresh, true))}</p>${externalLink(source.sourceUrl, safeUrl(source.sourceUrl))}</article>`).join("")}</div>
      <ul><li>Current reports are automated triage leads; profile relevance is not attack probability or proof of targeting.</li><li>Actor rankings use historical public reporting and require validation against current reporting before operational use.</li><li>The time picker filters report <code>publishedAt</code>, ATT&amp;CK <code>last_seen</code> and CISA <code>dateAdded</code>; it does not date undated actor relationships.</li><li>Infrastructure, domains, IP addresses, hashes and host/network artefacts are not collected.</li><li>KQL is schema reviewed against Microsoft Learn but requires tenant validation.</li></ul>
    </section>

    <footer class="report-footer"><p>Report generated from validated public source snapshots. Complete ranked data and methodology metadata remain available in the JSON export.</p></footer>
  `;
}

function preparePrintReport() {
  if (!state.profile) return;
  renderPrintReport();
  const safeDate = new Date().toISOString().slice(0, 10);
  document.title = `Threat Profile - ${state.profile.sector} - ${state.profile.country} - ${safeDate}`;
}

function restoreScreenTitle() {
  document.title = screenDocumentTitle;
}

function renderAll() {
  renderProfileHeader();
  renderJudgements();
  renderOverview();
  renderActors();
  renderTechniques();
  renderVulnerabilities();
  renderModels();
  renderPrintReport();
  setView(state.activeView, { updateHistory: false, scroll: false });
}

function buildProfile({ announceResult = false, pushHistory = false } = {}) {
  const sector = elements.sector.value;
  const country = elements.country.value;
  if (!sector || !country) return;

  const evidenceWindow = normalizeEvidenceWindowPreset(elements.evidenceWindow.value);
  const focusCount = normalizeTopFocus(elements.focusCount.value);
  elements.evidenceWindow.value = evidenceWindow;
  elements.focusCount.value = String(focusCount);

  state.profile = {
    organisation: elements.organisation.value.trim(),
    sector,
    country,
    technology: elements.technology.value.trim(),
    watchlist: elements.watchlist.value.trim(),
    evidenceWindow,
    focusCount,
  };
  state.rankedActors = scoreActors(state.intelligence.actors, sector, country, {
    sectors: state.intelligence.sectors,
    countries: state.intelligence.countries,
  });
  state.focusSelection = selectTopFocus(state.rankedActors, focusCount);
  state.focusActors = state.focusSelection.focused;
  state.techniques = aggregateTechniques(state.focusActors, state.intelligence.techniques);
  state.software = aggregateSoftware(state.focusActors, state.intelligence.software);

  const linkedCampaigns = relevantCampaigns(state.intelligence.campaigns, state.focusActors, state.intelligence.generatedAt);
  state.campaignEvidence = classifyCampaignsByWindow(linkedCampaigns, evidenceWindow, { generatedAt: state.intelligence.generatedAt });
  state.campaigns = state.campaignEvidence.inWindow;

  const relevantVulnerabilities = filterVulnerabilities(state.intelligence.vulnerabilities, state.profile.technology);
  state.kevEvidence = classifyKevsByWindow(relevantVulnerabilities, evidenceWindow, { generatedAt: state.intelligence.generatedAt });
  state.vulnerabilities = state.kevEvidence.inWindow;

  const matchedReports = matchCurrentReports(state.currentReportData.reports, state.profile);
  state.reportEvidence = classifyReportsByWindow(matchedReports, evidenceWindow, { generatedAt: state.currentReportData.generatedAt || state.intelligence.generatedAt });
  state.currentReports = state.reportEvidence.inWindow;
  state.currentEntities = groupCurrentEntities(state.currentReports);

  state.actorVisible = Math.max(10, state.focusSelection.actualCount);
  state.techniqueVisible = 20;
  state.kevVisible = 12;

  if (!state.rankedActors.some((actor) => actor.id === state.selectedActorId)) state.selectedActorId = null;
  if (!state.techniques.some((technique) => technique.id === state.selectedTechniqueId)) state.selectedTechniqueId = null;
  state.activeView = state.activeView || "overview";
  state.exampleProfile = !pushHistory && state.exampleProfile;

  elements.results.hidden = false;
  elements.error.hidden = true;
  elements.shareProfile.disabled = false;
  renderAll();
  if (pushHistory) updateUrl("push");
  else updateUrl("replace");
  if (announceResult) {
    const message = `OSINT brief built for ${profileName()}. ${state.currentReports.length} public reports and ${state.currentEntities.length} named entities fall inside ${evidenceWindowLabel()}.`;
    announce(message);
    elements.profileTitle.focus();
  }
}

function setView(view, { updateHistory = true, scroll = true } = {}) {
  if (!validViews.has(view)) view = "overview";
  state.activeView = view;
  let activePanel = null;
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== view;
    if (!panel.hidden) activePanel = panel;
  });
  document.querySelectorAll("[data-view]").forEach((link) => {
    if (link.dataset.view === view) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (updateHistory) updateUrl("push");
  if (scroll) activePanel?.scrollIntoView({ block: "start" });
}

function selectActor(actorId, { moveToActors = false } = {}) {
  state.selectedActorId = actorId;
  renderActors();
  renderModels();
  updateUrl("push");
  if (moveToActors) setView("actors", { updateHistory: false });
}

function selectTechnique(techniqueId, { moveToTechniques = false } = {}) {
  state.selectedTechniqueId = techniqueId;
  renderTechniques();
  updateUrl("push");
  if (moveToTechniques) setView("techniques", { updateHistory: false });
}

async function initialise() {
  elements.main.setAttribute("aria-busy", "true");
  elements.error.hidden = true;
  try {
    const [response, reportResponse] = await Promise.all([
      fetch("./data/intelligence.json", { cache: "no-store" }),
      fetch("./data/sources/current-reports.json", { cache: "no-store" }),
    ]);
    if (!response.ok) throw new Error(`Dataset request returned ${response.status}.`);
    if (!reportResponse.ok) throw new Error(`Current-report request returned ${reportResponse.status}.`);
    const [intelligence, currentReportData] = await Promise.all([response.json(), reportResponse.json()]);
    if (intelligence.schemaVersion !== 2 || !Array.isArray(intelligence.actors) || intelligence.actors.length < 100) {
      throw new Error("The validated intelligence snapshot is unavailable.");
    }
    if (currentReportData.schemaVersion !== 1 || !Array.isArray(currentReportData.reports)) {
      throw new Error("The automated current-report layer is unavailable.");
    }
    state.intelligence = intelligence;
    state.currentReportData = currentReportData;
    populateFilters();
    renderHealth();
    readProfileFromUrl();
    buildProfile();
  } catch (error) {
    elements.errorMessage.textContent = `${error.message} Try again shortly or ask the repository owner to inspect the source workflow.`;
    elements.error.hidden = false;
    elements.results.hidden = true;
    elements.healthLabel.textContent = "Dataset unavailable";
    elements.healthDot.className = "status-dot error";
    elements.healthSummary.textContent = "The profile dataset could not be validated.";
  } finally {
    elements.main.setAttribute("aria-busy", "false");
  }
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  state.exampleProfile = false;
  state.activeView = "overview";
  state.selectedActorId = null;
  state.selectedTechniqueId = null;
  buildProfile({ announceResult: true, pushHistory: true });
});

elements.editProfile.addEventListener("click", () => {
  elements.profileBuilder.scrollIntoView({ block: "center" });
  elements.sector.focus();
});

elements.healthButton.addEventListener("click", () => {
  const expanded = elements.healthButton.getAttribute("aria-expanded") === "true";
  elements.healthButton.setAttribute("aria-expanded", String(!expanded));
  elements.healthPopover.hidden = expanded;
});

elements.retryButton.addEventListener("click", initialise);

document.addEventListener("click", (event) => {
  const reportButton = event.target.closest("[data-print-report]");
  if (reportButton) {
    preparePrintReport();
    announce("Printable report prepared. Opening the browser print dialog.");
    requestAnimationFrame(() => {
      window.print();
      setTimeout(restoreScreenTitle, 0);
    });
    return;
  }
  const viewLink = event.target.closest("[data-view], [data-view-link]");
  if (viewLink) {
    event.preventDefault();
    setView(viewLink.dataset.view || viewLink.dataset.viewLink);
    return;
  }
  const actorButton = event.target.closest("[data-actor-id]");
  if (actorButton) {
    selectActor(actorButton.dataset.actorId, { moveToActors: !actorButton.classList.contains("actor-row") });
    return;
  }
  const techniqueButton = event.target.closest("[data-technique-id]");
  if (techniqueButton) {
    selectTechnique(techniqueButton.dataset.techniqueId, { moveToTechniques: !techniqueButton.classList.contains("technique-row") });
    return;
  }
  const copyButton = event.target.closest("[data-copy-detection]");
  if (copyButton) {
    const detection = DETECTIONS.find((entry) => entry.id === copyButton.dataset.copyDetection);
    if (detection) copyText(detection.kql, `${detection.title} KQL copied. Tenant validation is still required.`);
  }
});

elements.actorSearch.addEventListener("input", () => {
  state.actorVisible = 10;
  renderActors();
});
elements.actorBandFilter.addEventListener("change", () => {
  state.actorVisible = 10;
  renderActors();
});
elements.clearActorFilters.addEventListener("click", () => {
  elements.actorSearch.value = "";
  elements.actorBandFilter.value = "all";
  state.actorVisible = 10;
  renderActors();
  elements.actorSearch.focus();
});
elements.actorMore.addEventListener("click", () => {
  state.actorVisible += 10;
  renderActors();
});

elements.techniqueSearch.addEventListener("input", () => {
  state.techniqueVisible = 20;
  renderTechniques();
});
elements.tacticFilter.addEventListener("change", () => {
  state.techniqueVisible = 20;
  renderTechniques();
});
elements.detectionFilter.addEventListener("change", () => {
  state.techniqueVisible = 20;
  renderTechniques();
});
elements.clearTechniqueFilters.addEventListener("click", () => {
  elements.techniqueSearch.value = "";
  elements.tacticFilter.value = "all";
  elements.detectionFilter.checked = false;
  state.techniqueVisible = 20;
  renderTechniques();
  elements.techniqueSearch.focus();
});
elements.techniqueMore.addEventListener("click", () => {
  state.techniqueVisible += 20;
  renderTechniques();
});

elements.kevMore.addEventListener("click", () => {
  state.kevVisible += 12;
  renderVulnerabilities();
});

elements.modelActorSelect.addEventListener("change", () => {
  state.selectedActorId = elements.modelActorSelect.value || null;
  renderActors();
  renderModels();
  updateUrl("push");
});

elements.shareProfile.addEventListener("click", () => {
  copyText(currentUrl().toString(), "Share link copied. Organisation, technology and watchlist context were excluded for privacy.");
});

elements.exportProfile.addEventListener("click", () => {
  if (!state.profile) return;
  const slug = `${state.profile.sector}-${state.profile.country}`
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  downloadJson(`${slug || "threat-profile"}.json`, {
    schemaVersion: 3,
    generatedAt: state.intelligence.generatedAt,
    methodology: {
      profileFit: "specificity-weighted sector and country context",
      confidence: "separate from profile fit; historical aggregate targeting context requires validation against current intelligence",
      analysisFocus: "approved Top-N actor cohort with every score tie at the cutoff retained; downstream techniques, software, campaigns and KQL priorities are recalculated from this cohort",
      datedEvidenceWindow: "public reports use source publishedAt, campaigns use ATT&CK last_seen, and KEV uses CISA dateAdded; undated actor targeting and ATT&CK relationships are not filtered",
      techniqueScore: "minimum of weighted and documentation-adjusted actor coverage",
      campaignRecency: "ATT&CK last_seen only; catalogue modified dates are never substituted",
      kevExposure: "keyword matches are possible matches, never confirmed exposure",
      reportRecency: "publishedAt is report-publication recency, not necessarily an activity date",
    },
    sourceHealth: state.intelligence.health,
    coverage: state.intelligence.coverage,
    privacy: {
      containsOrganisationContext: Boolean(state.profile.organisation),
      containsTechnologyContext: Boolean(state.profile.technology),
      containsWatchlistContext: Boolean(state.profile.watchlist),
      sharingNotice: "This complete export may contain user-entered context. Review it before sharing.",
    },
    profile: {
      organisation: state.profile.organisation || null,
      sector: state.profile.sector,
      country: state.profile.country,
      technology: state.profile.technology || null,
      watchlist: state.profile.watchlist || null,
      evidenceWindow: state.campaignEvidence.window,
      analysisFocus: {
        requestedCount: state.focusSelection.requestedCount,
        actualCount: state.focusSelection.actualCount,
        cutoffRank: state.focusSelection.cutoffRank,
        includedCutoffTies: state.focusSelection.includedCutoffTies,
      },
      jointTargetingEvidence: false,
      namedOrganisationTargetingEvidence: false,
    },
    results: {
      actors: {
        allCandidates: state.rankedActors,
        analysisFocus: state.focusActors,
      },
      currentReporting: {
        sourceMetadata: {
          generatedAt: state.currentReportData.generatedAt,
          methodology: state.currentReportData.methodology,
          sources: state.currentReportData.sources,
        },
        inWindow: state.currentReports,
        entities: state.currentEntities,
        excluded: state.reportEvidence.excluded,
        allProfileMatches: state.reportEvidence.all,
      },
      campaigns: {
        inWindow: state.campaigns,
        excluded: state.campaignEvidence.excluded,
        allFocusedActorCampaigns: state.campaignEvidence.all,
      },
      techniques: state.techniques,
      software: state.software,
      vulnerabilities: {
        inWindow: state.vulnerabilities,
        excluded: state.kevEvidence.excluded,
        allContextMatches: state.kevEvidence.all,
      },
    },
  });
  showFeedback(state.profile.organisation || state.profile.technology || state.profile.watchlist
    ? "Complete profile exported. It includes entered context—review it before sharing."
    : "Complete profile exported.");
});

elements.exportAttack.addEventListener("click", () => {
  if (!state.profile) return;
  downloadJson(
    "attack-navigator-layer.json",
    navigatorLayer(publicProfileName(), state.techniques, state.intelligence.versions?.attack, {
      focus: focusLabel(),
      evidenceWindow: evidenceWindowLabel(),
    }),
  );
  showFeedback("ATT&CK Navigator layer downloaded.");
});

window.addEventListener("beforeprint", preparePrintReport);
window.addEventListener("afterprint", restoreScreenTitle);

window.addEventListener("popstate", () => {
  if (!state.intelligence) return;
  readProfileFromUrl();
  buildProfile();
});

initialise();
