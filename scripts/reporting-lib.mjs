import { createHash } from "node:crypto";

const AMBIGUOUS_ENTITIES = new Set([
  "agent", "apple", "backdoor", "black", "blue", "cloud", "comet", "dark", "dragon",
  "energy", "ghost", "group", "help", "light", "lotus", "menu", "night", "oil", "play",
  "power", "project", "red", "root", "saint", "shadow", "shell", "silence", "snake", "storm",
  "system", "team", "web", "windows", "winter", "zero",
]);

const SECTOR_TERMS = Object.freeze({
  Aerospace: ["aerospace", "aviation", "aircraft"],
  Agriculture: ["agriculture", "agricultural", "farming", "food production"],
  Automotive: ["automotive", "vehicle manufacturer", "car manufacturer"],
  Banks: ["bank", "banking", "credit institution"],
  "Casinos Gambling": ["casino", "gambling", "gaming operator"],
  Chemical: ["chemical industry", "chemicals"],
  Commercial: ["commercial organisations", "commercial organizations"],
  Construction: ["construction", "building contractor"],
  "Credit Unions": ["credit union"],
  Defense: ["defence", "defense", "military contractor"],
  Education: ["education", "university", "universities", "school", "academic sector"],
  Electronics: ["electronics", "semiconductor", "chip manufacturer"],
  Energy: ["energy sector", "oil and gas", "power generation"],
  Entertainment: ["entertainment", "film studio", "music industry"],
  "Financial Services": ["financial services", "finance sector", "financial institution", "fintech"],
  Government: ["government", "public sector", "government agency", "ministry"],
  Healthcare: ["healthcare", "health care", "hospital", "medical provider", "health sector"],
  "High Tech": ["high tech", "technology company", "software company"],
  "Hospitality Leisure": ["hospitality", "hotel", "leisure sector"],
  "Human Rights": ["human rights organisation", "human rights organization", "activist"],
  Infrastructure: ["critical infrastructure", "infrastructure operator"],
  Insurance: ["insurance", "insurer"],
  Legal: ["legal sector", "law firm", "legal services"],
  Manufacturing: ["manufacturing", "manufacturer", "industrial sector"],
  Maritime: ["maritime", "shipping", "port operator"],
  Media: ["media organisation", "media organization", "news organisation", "journalist"],
  Mining: ["mining", "minerals sector"],
  NGOs: ["non-governmental organisation", "non-governmental organization", "ngo"],
  "Non Profit": ["non-profit", "nonprofit", "charity"],
  Nuclear: ["nuclear sector", "nuclear facility"],
  Pharmaceuticals: ["pharmaceutical", "drug manufacturer", "biotechnology"],
  Retail: ["retail", "retailer", "e-commerce", "ecommerce"],
  "Semi Conductors": ["semiconductor", "chipmaker", "chip manufacturer"],
  Technology: ["technology sector", "technology company", "software company", "saas provider"],
  Telecommunications: ["telecommunications", "telecom", "mobile operator"],
  "Think Tanks": ["think tank", "policy institute"],
  Transportation: ["transportation", "transport operator", "railway", "airline"],
  "Travel Services": ["travel services", "travel agency", "tour operator"],
  Utilities: ["utility provider", "utilities sector", "electricity provider", "water utility"],
  "Video Games": ["video game", "gaming studio", "games company"],
  Water: ["water sector", "water utility", "water provider"],
});

const COUNTRY_ALIASES = Object.freeze({
  AU: ["australia", "australian"],
  CA: ["canada", "canadian"],
  CN: ["china", "chinese", "prc"],
  DE: ["germany", "german"],
  ES: ["spain", "spanish"],
  FR: ["france", "french"],
  GB: ["united kingdom", "uk", "britain", "british"],
  IE: ["ireland", "irish"],
  IL: ["israel", "israeli"],
  IN: ["india", "indian"],
  IR: ["iran", "iranian"],
  IT: ["italy", "italian"],
  JP: ["japan", "japanese"],
  KP: ["north korea", "north korean", "dprk"],
  KR: ["south korea", "south korean", "republic of korea"],
  NL: ["netherlands", "dutch"],
  NZ: ["new zealand"],
  PL: ["poland", "polish"],
  RU: ["russia", "russian"],
  TR: ["turkiye", "turkey", "turkish"],
  TW: ["taiwan", "taiwanese"],
  UA: ["ukraine", "ukrainian"],
  US: ["united states", "u s", "usa", "american"],
});

function unique(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function normaliseText(value) {
  return ` ${String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()} `;
}

function containsPhrase(normalisedText, phrase) {
  const candidate = normaliseText(phrase).trim();
  return candidate.length > 1 && normalisedText.includes(` ${candidate} `);
}

function decodeEntities(value) {
  const named = {
    amp: "&", apos: "'", gt: ">", lt: "<", nbsp: " ", quot: '"',
    ndash: "–", mdash: "—", hellip: "…", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“",
  };
  return String(value || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number.parseInt(code, 10)))
    .replace(/&([a-z]+);/gi, (match, name) => named[name.toLowerCase()] ?? match);
}

function plainText(value) {
  return decodeEntities(value)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function summary(value, maximum = 900) {
  const clean = plainText(value);
  return clean.length > maximum ? `${clean.slice(0, maximum - 1).trimEnd()}…` : clean;
}

function tagValue(block, tag) {
  const escaped = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const expression = new RegExp(`<(?:(?:[\\w-]+):)?${escaped}\\b[^>]*>([\\s\\S]*?)<\\/(?:(?:[\\w-]+):)?${escaped}>`, "i");
  return expression.exec(block)?.[1] || "";
}

function safeUrl(value) {
  try {
    const url = new URL(plainText(value));
    if (url.protocol !== "https:" || url.username || url.password) return null;
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

function itemUrl(block) {
  const direct = safeUrl(tagValue(block, "link"));
  if (direct) return direct;
  const atomLink = /<link\b[^>]*\bhref=(?:"([^"]+)"|'([^']+)')[^>]*>/i.exec(block);
  return safeUrl(atomLink?.[1] || atomLink?.[2] || tagValue(block, "guid"));
}

function dateOnly(value) {
  if (!value) return null;
  const date = new Date(plainText(value));
  return Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : null;
}

export function parseSyndicationFeed(xml) {
  const body = String(xml || "");
  const rssItems = [...body.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)].map((match) => match[1]);
  const atomItems = [...body.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)].map((match) => match[1]);
  return [...rssItems, ...atomItems]
    .map((block) => {
      const title = summary(tagValue(block, "title"), 240);
      const url = itemUrl(block);
      const publishedAt = dateOnly(
        tagValue(block, "pubDate") || tagValue(block, "published") || tagValue(block, "updated") || tagValue(block, "date"),
      );
      const description = summary(
        tagValue(block, "description") || tagValue(block, "summary") || tagValue(block, "encoded") || tagValue(block, "content"),
      );
      if (!title || !url) return null;
      return { title, url, publishedAt, summary: description };
    })
    .filter(Boolean);
}

function entityAliases(entity) {
  return unique([entity.name, ...(entity.aliases || [])])
    .map((alias) => ({ alias, normalised: normaliseText(alias).trim() }))
    .filter(({ normalised }) => {
      if (normalised.length < 4 || AMBIGUOUS_ENTITIES.has(normalised)) return false;
      const singleWord = !normalised.includes(" ");
      return !singleWord || normalised.length >= 5 || /\d/.test(normalised);
    });
}

function entityIndex(actors, software) {
  return [
    ...(actors || []).map((actor) => ({ id: actor.id, name: actor.name, entityType: "threat-actor-group", aliases: entityAliases(actor) })),
    ...(software || [])
      .filter((entry) => entry.kind === "malware")
      .map((entry) => ({ id: entry.id, name: entry.name, entityType: "malware-family", aliases: entityAliases(entry) })),
  ].filter((entry) => entry.aliases.length);
}

function findEntities(text, index) {
  const normalised = normaliseText(text);
  return index
    .filter((entity) => entity.aliases.some(({ alias }) => containsPhrase(normalised, alias)))
    .map(({ id, name, entityType }) => ({ id, name, entityType }));
}

function discoveredActorEntities(title, text) {
  const candidates = [];
  const value = plainText(title);
  for (const match of plainText(text).matchAll(/\b(?:APT|UNC|FIN|TA|DEV|STORM)-?\d{2,5}\b/gi)) candidates.push(match[0]);
  for (const match of value.matchAll(/\b([A-Z][A-Z0-9-]{3,}\s+[A-Z][A-Z0-9-]{3,})(?=\s+(?:[Tt]argets?|[Tt]argeting|[Cc]ampaign|[Aa]ctivity|[Aa]ttacks?))/g)) {
    candidates.push(match[1]);
  }
  for (const match of value.matchAll(/\b([A-Z][a-z]+\s+(?:Typhoon|Blizzard|Sleet|Sandstorm|Tsunami|Tempest))\b/g)) {
    candidates.push(match[1]);
  }
  return unique(candidates).map((name) => ({
    id: `UNMAPPED-${createHash("sha256").update(name.toLowerCase()).digest("hex").slice(0, 10)}`,
    name,
    entityType: "unmapped-threat-actor",
  }));
}

function reportEntities(title, text, index) {
  const known = findEntities(text, index);
  const knownNames = new Set(known.map((entry) => normaliseText(entry.name).trim()));
  return [...known, ...discoveredActorEntities(title, text).filter((entry) => !knownNames.has(normaliseText(entry.name).trim()))];
}

function findSectors(text, sectors) {
  const normalised = normaliseText(text);
  return (sectors || []).filter((sector) => {
    const terms = SECTOR_TERMS[sector] || [sector];
    return terms.some((term) => containsPhrase(normalised, term));
  });
}

function findCountries(text, countryCodes) {
  const normalised = normaliseText(text);
  const display = new Intl.DisplayNames(["en"], { type: "region" });
  return (countryCodes || []).filter((code) => {
    const name = display.of(code);
    const terms = unique([name, ...(COUNTRY_ALIASES[code] || [])]);
    return terms.some((term) => containsPhrase(normalised, term));
  });
}

function activityType(title, text, entities) {
  const normalisedTitle = normaliseText(title);
  const normalisedText = normaliseText(text);
  if (/\b(campaign|operation)\b/.test(normalisedTitle) || /\b(named campaign|campaign tracked as|operation known as)\b/.test(normalisedText)) {
    return "campaign-report";
  }
  if (entities.some((entry) => ["threat-actor-group", "unmapped-threat-actor"].includes(entry.entityType))) return "actor-report";
  if (entities.some((entry) => entry.entityType === "malware-family")) return "malware-report";
  return "security-advisory";
}

export function normaliseCurrentReports(feedResults, intelligence, generatedAt = new Date().toISOString()) {
  const index = entityIndex(intelligence?.actors, intelligence?.software);
  const reports = [];
  const sources = [];

  for (const result of feedResults || []) {
    const parsed = parseSyndicationFeed(result.body)
      .sort((a, b) => String(b.publishedAt || "").localeCompare(String(a.publishedAt || "")))
      .slice(0, result.maximumItems || 80);
    sources.push({
      id: result.id,
      name: result.name,
      authority: result.authority,
      url: result.url,
      homepage: result.homepage,
      status: result.status || "current",
      checkedAt: generatedAt,
      lastSuccessfulRefresh: result.lastSuccessfulRefresh || generatedAt,
      recordCount: parsed.length,
      error: result.error || null,
    });

    for (const item of parsed) {
      const searchable = `${item.title} ${item.summary}`;
      const entities = reportEntities(item.title, searchable, index);
      const sectors = findSectors(searchable, intelligence?.sectors);
      const countries = findCountries(searchable, intelligence?.countries);
      reports.push({
        id: `osint-${createHash("sha256").update(item.url).digest("hex").slice(0, 16)}`,
        title: item.title,
        summary: item.summary,
        publishedAt: item.publishedAt,
        url: item.url,
        source: { id: result.id, name: result.name, authority: result.authority },
        activityType: activityType(item.title, searchable, entities),
        entities,
        actorIds: entities.filter((entry) => entry.entityType === "threat-actor-group").map((entry) => entry.id),
        sectors,
        countries,
      });
    }
  }

  const deduplicated = [...new Map(reports.map((report) => [report.url, report])).values()]
    .sort((a, b) => String(b.publishedAt || "").localeCompare(String(a.publishedAt || "")) || a.title.localeCompare(b.title));

  return {
    schemaVersion: 1,
    generatedAt,
    methodology: {
      purpose: "Automated, dated public reporting for analyst triage.",
      matchingPolicy: "A report is matched from its own text. Country-only matches never create sector relevance.",
      evidencePolicy: "A direct name mention is not proof of compromise or deliberate targeting; analysts must verify the source.",
      campaignPolicy: "Campaign labels are used only when the source itself describes a campaign or named operation.",
    },
    sources,
    reports: deduplicated,
  };
}

function validDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value || "") && Number.isFinite(new Date(`${value}T00:00:00Z`).getTime());
}

export function validateCurrentReports(value) {
  const errors = [];
  if (!value || typeof value !== "object") return ["current reports are not an object"];
  if (value.schemaVersion !== 1) errors.push("current-report schemaVersion must be 1");
  if (!Number.isFinite(new Date(value.generatedAt).getTime())) errors.push("current reports need a valid generatedAt timestamp");
  if (!Array.isArray(value.sources) || value.sources.length < 3) errors.push("current-report source coverage is below 3");
  if (!Array.isArray(value.reports) || value.reports.length < 1) errors.push("current-report coverage is empty");

  const ids = new Set();
  const urls = new Set();
  for (const report of value.reports || []) {
    const prefix = report?.id || "unnamed report";
    if (!/^osint-[a-f0-9]{16}$/.test(report?.id || "")) errors.push(`${prefix} has an invalid ID`);
    if (ids.has(report?.id)) errors.push(`${prefix} is duplicated`);
    ids.add(report?.id);
    if (!report?.title || typeof report.title !== "string") errors.push(`${prefix} needs a title`);
    if (report?.publishedAt !== null && !validDate(report?.publishedAt)) errors.push(`${prefix} has an invalid publication date`);
    if (!safeUrl(report?.url)) errors.push(`${prefix} needs an HTTPS URL`);
    if (urls.has(report?.url)) errors.push(`${prefix} duplicates a report URL`);
    urls.add(report?.url);
    if (!Array.isArray(report?.entities) || !Array.isArray(report?.sectors) || !Array.isArray(report?.countries)) {
      errors.push(`${prefix} has incomplete correlation fields`);
    }
  }
  return errors;
}

export function assertValidCurrentReports(value) {
  const errors = validateCurrentReports(value);
  if (errors.length) throw new Error(`Current report validation failed:\n- ${errors.join("\n- ")}`);
}
