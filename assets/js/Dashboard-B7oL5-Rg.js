const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/OptimizedMap-m10PmnUE.js","assets/js/index-DlBwyd5U.js","assets/js/react-vendor-CSPBeBBz.js","assets/js/leaflet-vendor-BcXhkSxI.js","assets/css/index-CuWVk-Hd.css","assets/css/OptimizedMap-Dlna1-ep.css","assets/js/TabbedSidebar-Ckn0YuF5.js","assets/css/TabbedSidebar-T6IH_SY-.css","assets/js/ExportPanel-BHM7wuwe.js","assets/js/api-0s8aYwKN.js","assets/js/utils-Cs_fMHvp.js","assets/css/ExportPanel-rPKiQ0eQ.css"])))=>i.map(i=>d[i]);
import { _ as __vitePreload, j as jsxRuntimeExports, L as LoadingSpinner } from "./index-DlBwyd5U.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { A as API_CONFIG, g as getApiBaseUrl } from "./api-0s8aYwKN.js";
import "./react-vendor-CSPBeBBz.js";
var __async$3 = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
function parseURN(urn) {
  const parts = urn.split(":");
  let state;
  let municipality;
  let type = "lei";
  let number;
  let date;
  let chamber;
  if (parts.length > 2) {
    const locationPart = parts[2];
    if (locationPart.includes("congresso.nacional")) {
      chamber = "Congresso Nacional";
    } else if (locationPart.includes("camara.leg.br") || locationPart.includes("camara.municipal")) {
      chamber = "Câmara dos Deputados";
    } else if (locationPart.includes("senado.leg.br")) {
      chamber = "Senado Federal";
    } else if (locationPart.includes("federal") || locationPart === "br") {
      chamber = "DOU/Planalto";
    } else if (locationPart.includes("estadual")) {
      chamber = "Governo Estadual";
    } else if (locationPart.includes("municipal")) {
      chamber = "Governo Municipal";
    } else if (locationPart.includes("tribunal")) {
      chamber = "Poder Judiciário";
    }
    if (locationPart && locationPart !== "br") {
      const locationParts = locationPart.split(";");
      if (locationParts.length > 0) {
        const mainLocation = locationParts[0];
        if (mainLocation.includes(".")) {
          const [stateCode, municipalityCode] = mainLocation.split(".");
          state = normalizeStateName(stateCode);
          if (municipalityCode) {
            municipality = normalizeMunicipalityName(municipalityCode);
          }
        } else {
          state = normalizeStateName(mainLocation);
        }
      }
    }
  }
  if (parts.length > 3) {
    const typePart = parts[3];
    if (typePart.includes(":")) {
      type = typePart.split(":")[0];
    } else {
      type = typePart;
    }
    type = normalizeDocumentType(type);
  }
  if (parts.length > 4) {
    const lastPart = parts[parts.length - 1];
    const datePart = parts[parts.length - 2];
    if (datePart && datePart.match(/\d{4}-\d{2}-\d{2}/)) {
      try {
        date = new Date(datePart);
      } catch (e) {
        date = /* @__PURE__ */ new Date();
      }
    }
    if (lastPart && lastPart.match(/\d+/)) {
      number = lastPart.replace(/[^\d]/g, "");
    }
  }
  return { state, municipality, type, number, date, chamber };
}
function normalizeStateName(stateCode) {
  const stateMap = {
    "sao.paulo": "SP",
    "rio.de.janeiro": "RJ",
    "minas.gerais": "MG",
    "rio.grande.sul": "RS",
    "parana": "PR",
    "bahia": "BA",
    "distrito.federal": "DF",
    "espirito.santo": "ES",
    "goias": "GO",
    "santa.catarina": "SC",
    "ceara": "CE",
    "pernambuco": "PE",
    "para": "PA",
    "maranhao": "MA",
    "paraiba": "PB",
    "alagoas": "AL",
    "sergipe": "SE",
    "rondonia": "RO",
    "acre": "AC",
    "amazonas": "AM",
    "roraima": "RR",
    "amapa": "AP",
    "tocantins": "TO",
    "mato.grosso": "MT",
    "mato.grosso.sul": "MS",
    "piauí": "PI"
  };
  return stateMap[stateCode] || stateCode.toUpperCase();
}
function normalizeMunicipalityName(municipalityCode) {
  return municipalityCode.split(".").map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
}
function normalizeDocumentType(type) {
  const typeMap = {
    "lei": "lei",
    "decreto": "decreto",
    "decreto.lei": "decreto_lei",
    "medida.provisoria": "medida_provisoria",
    "portaria": "portaria",
    "resolucao": "resolucao",
    "acordao": "acordao",
    "instrucao.normativa": "instrucao_normativa",
    "emenda.constitucional": "emenda_constitucional"
  };
  return typeMap[type] || type;
}
function generateKeywords(searchTerm, title) {
  const keywords = /* @__PURE__ */ new Set();
  keywords.add(searchTerm.toLowerCase());
  const titleWords = title.toLowerCase().replace(/[^\w\s]/g, " ").split(/\s+/).filter((word) => word.length > 3);
  titleWords.forEach((word) => keywords.add(word));
  const transportTerms = [
    "transporte",
    "rodoviário",
    "carga",
    "logística",
    "frete",
    "fretamento",
    "caminhão",
    "veículo",
    "rodovia",
    "tráfego"
  ];
  transportTerms.forEach((term) => {
    if (title.toLowerCase().includes(term)) {
      keywords.add(term);
    }
  });
  return Array.from(keywords).slice(0, 8);
}
function parseCSVLine(line) {
  const result = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' && line[i - 1] !== "\\\\") {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      result.push(current.trim().replace(/^"|"$/g, ""));
      current = "";
    } else {
      current += char;
    }
  }
  result.push(current.trim().replace(/^"|"$/g, ""));
  return result;
}
function generateCitation(doc, urn) {
  var _a, _b;
  const year = doc.date ? doc.date.getFullYear() : (/* @__PURE__ */ new Date()).getFullYear();
  const state = doc.state || "BRASIL";
  if (doc.type === "lei" && doc.number) {
    return `${state}. Lei nº ${doc.number}, de ${((_a = doc.date) == null ? void 0 : _a.toLocaleDateString("pt-BR")) || "data não informada"}. Disponível em: ${doc.url}. Acesso em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}.`;
  } else if (doc.type === "decreto" && doc.number) {
    return `${state}. Decreto nº ${doc.number}, de ${((_b = doc.date) == null ? void 0 : _b.toLocaleDateString("pt-BR")) || "data não informada"}. Disponível em: ${doc.url}. Acesso em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}.`;
  } else {
    return `${doc.title}. ${state}, ${year}. Disponível em: ${doc.url}. Acesso em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}.`;
  }
}
function parseCSVData(csvContent) {
  const lines = csvContent.split(/\r?\n/).filter((line) => line.trim() !== "");
  console.log(`CSV split into ${lines.length} lines`);
  if (lines.length < 2) {
    console.warn("CSV content has no data rows.");
    return [];
  }
  if (lines[0]) {
    lines[0] = lines[0].replace(/^\uFEFF/, "");
  }
  const headers = parseCSVLine(lines[0]).map((h) => h.trim().replace(/['"]+/g, ""));
  console.log("CSV Headers:", headers);
  console.log("First line raw:", lines[0].substring(0, 50));
  const documents = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const values = parseCSVLine(line);
    if (values.length !== headers.length) {
      console.warn(`Skipping malformed CSV row ${i + 1}: Expected ${headers.length} fields, but found ${values.length}. Line: "${line}"`);
      continue;
    }
    const row = {
      search_term: values[0] || "",
      date_searched: values[1] || "",
      url: values[2] || "",
      title: values[3] || "No Title Provided",
      urn: values[4] || ""
    };
    if (!row.urn) {
      console.warn(`Skipping row ${i + 1} due to missing URN.`);
      continue;
    }
    const { state, municipality, type, number, date, chamber } = parseURN(row.urn);
    const docDate = date || /* @__PURE__ */ new Date();
    documents.push({
      id: row.urn,
      title: row.title,
      summary: `Document retrieved on ${row.date_searched} for search term "${row.search_term}".`,
      type: type || "lei",
      date: docDate.toISOString(),
      keywords: generateKeywords(row.search_term, row.title),
      state: state || "Federal",
      municipality,
      url: row.url,
      status: "sancionado",
      chamber: chamber || "Unknown",
      number,
      source: "LexML",
      citation: generateCitation({ title: row.title, url: row.url, date: docDate, state, type, number })
    });
  }
  console.log(`Successfully parsed ${documents.length} documents from CSV.`);
  return documents;
}
function loadCSVLegislativeData() {
  return __async$3(this, null, function* () {
    const basePath = "/monitor-legislativo-v4/";
    const CSV_URL = `${basePath}lexml_transport_results_20250606_123100.csv`;
    console.log(`Fetching real CSV data from: ${CSV_URL}`);
    try {
      const response = yield fetch(CSV_URL);
      if (!response.ok) {
        console.warn(`CSV file not accessible (${response.status}), falling back to embedded real data`);
        const { realLegislativeData, validateDataIntegrity } = yield __vitePreload(() => import("./real-legislative-data-Br35ZUF3.js"), true ? [] : void 0);
        if (!validateDataIntegrity()) {
          throw new Error("Embedded real data failed integrity validation");
        }
        console.log(`Using embedded real legislative data: ${realLegislativeData.length} documents from LexML`);
        return realLegislativeData;
      }
      let csvContent = yield response.text();
      if (!csvContent) {
        throw new Error("CSV file is empty or could not be read.");
      }
      csvContent = csvContent.replace(/^\uFEFF/, "");
      console.log("CSV content first 100 chars:", csvContent.substring(0, 100));
      const parsedData = parseCSVData(csvContent);
      if (parsedData.length === 0) {
        throw new Error("CSV file contains no valid legislative documents.");
      }
      console.log(`Successfully loaded ${parsedData.length} documents from CSV file`);
      return parsedData;
    } catch (error) {
      console.error("Error loading CSV legislative data:", error);
      try {
        const { realLegislativeData, validateDataIntegrity } = yield __vitePreload(() => import("./real-legislative-data-Br35ZUF3.js"), true ? [] : void 0);
        if (!validateDataIntegrity()) {
          throw new Error("Embedded real data failed integrity validation");
        }
        console.log(`Fallback: Using embedded real legislative data: ${realLegislativeData.length} documents from LexML`);
        return realLegislativeData;
      } catch (fallbackError) {
        console.error("Even embedded real data failed to load:", fallbackError);
        throw new Error(`Unable to load any real legislative data source. Please check data availability.`);
      }
    }
  });
}
let csvDataCache = null;
(() => __async$3(null, null, function* () {
  try {
    console.log("🔥 LOADING REAL LEGISLATIVE DATA...");
    csvDataCache = yield loadCSVLegislativeData();
    if (csvDataCache && csvDataCache.length > 0) {
      console.log(`✅ SUCCESS: Loaded ${csvDataCache.length} real documents`);
    } else {
      console.error("❌ Data loading failed - no data returned");
    }
  } catch (error) {
    console.error("❌ CRITICAL: Failed to load real legislative data on module import:", error);
    console.error("🚨 Academic integrity requires real data sources only");
    console.error("📋 Action required: Check data availability or API connectivity");
  }
}))();
var __defProp$2 = Object.defineProperty;
var __defProps$2 = Object.defineProperties;
var __getOwnPropDescs$2 = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols$2 = Object.getOwnPropertySymbols;
var __hasOwnProp$2 = Object.prototype.hasOwnProperty;
var __propIsEnum$2 = Object.prototype.propertyIsEnumerable;
var __defNormalProp$2 = (obj, key, value) => key in obj ? __defProp$2(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues$2 = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp$2.call(b, prop))
      __defNormalProp$2(a, prop, b[prop]);
  if (__getOwnPropSymbols$2)
    for (var prop of __getOwnPropSymbols$2(b)) {
      if (__propIsEnum$2.call(b, prop))
        __defNormalProp$2(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps$2 = (a, b) => __defProps$2(a, __getOwnPropDescs$2(b));
var __publicField$1 = (obj, key, value) => __defNormalProp$2(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async$2 = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
class ApiClient {
  constructor(config) {
    __publicField$1(this, "config");
    __publicField$1(this, "cache", /* @__PURE__ */ new Map());
    var _a, _b, _c, _d;
    this.config = {
      baseUrl: config.baseUrl,
      version: config.version,
      timeout: (_a = config.timeout) != null ? _a : 3e4,
      retries: (_b = config.retries) != null ? _b : 3,
      cacheEnabled: (_c = config.cacheEnabled) != null ? _c : true,
      cacheTTL: (_d = config.cacheTTL) != null ? _d : 3e5
      // 5 minutes
    };
  }
  getCacheKey(endpoint, params) {
    return `${endpoint}:${JSON.stringify(params || {})}`;
  }
  getFromCache(key) {
    if (!this.config.cacheEnabled) return null;
    const entry = this.cache.get(key);
    if (!entry) return null;
    const now = Date.now();
    if (now - entry.timestamp > this.config.cacheTTL) {
      this.cache.delete(key);
      return null;
    }
    return entry.data;
  }
  saveToCache(key, data) {
    if (!this.config.cacheEnabled) return;
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }
  fetchWithRetry(_0, _1) {
    return __async$2(this, arguments, function* (url, options, retries = this.config.retries) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
      try {
        const response = yield fetch(url, __spreadProps$2(__spreadValues$2({}, options), {
          signal: controller.signal
        }));
        clearTimeout(timeoutId);
        if (response.ok) {
          return response;
        }
        if (response.status >= 400 && response.status < 500) {
          throw new ApiError(
            `API Error: ${response.status} ${response.statusText}`,
            response.status
          );
        }
        if (retries > 0 && response.status >= 500) {
          yield this.delay(1e3 * (this.config.retries - retries + 1));
          return this.fetchWithRetry(url, options, retries - 1);
        }
        throw new ApiError(
          `API Error: ${response.status} ${response.statusText}`,
          response.status
        );
      } catch (error) {
        clearTimeout(timeoutId);
        if (error instanceof ApiError) {
          throw error;
        }
        if (error instanceof Error) {
          if (error.name === "AbortError") {
            throw new ApiError("Request timeout", 0);
          }
          if (retries > 0) {
            yield this.delay(1e3 * (this.config.retries - retries + 1));
            return this.fetchWithRetry(url, options, retries - 1);
          }
        }
        throw new ApiError("Network error", 0);
      }
    });
  }
  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  get(endpoint, params) {
    return __async$2(this, null, function* () {
      const cacheKey = this.getCacheKey(endpoint, params);
      const cached = this.getFromCache(cacheKey);
      if (cached !== null) {
        return cached;
      }
      const queryString = params ? `?${new URLSearchParams(params).toString()}` : "";
      const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}${queryString}`;
      const response = yield this.fetchWithRetry(url, {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        }
      });
      const data = yield response.json();
      this.saveToCache(cacheKey, data);
      return data;
    });
  }
  post(endpoint, body) {
    return __async$2(this, null, function* () {
      const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}`;
      const response = yield this.fetchWithRetry(url, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });
      return response.json();
    });
  }
  clearCache() {
    this.cache.clear();
  }
  clearCacheForEndpoint(endpoint) {
    const keysToDelete = [];
    for (const key of this.cache.keys()) {
      if (key.startsWith(endpoint + ":")) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach((key) => this.cache.delete(key));
  }
}
class ApiError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.name = "ApiError";
  }
}
const apiClient = new ApiClient({
  baseUrl: getApiBaseUrl(),
  version: "v1",
  timeout: API_CONFIG.timeout,
  cacheEnabled: true,
  cacheTTL: Number(void 0) || 3e5
});
var apiClient_default = apiClient;
var __defProp$1 = Object.defineProperty;
var __defProps$1 = Object.defineProperties;
var __getOwnPropDescs$1 = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols$1 = Object.getOwnPropertySymbols;
var __hasOwnProp$1 = Object.prototype.hasOwnProperty;
var __propIsEnum$1 = Object.prototype.propertyIsEnumerable;
var __defNormalProp$1 = (obj, key, value) => key in obj ? __defProp$1(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues$1 = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp$1.call(b, prop))
      __defNormalProp$1(a, prop, b[prop]);
  if (__getOwnPropSymbols$1)
    for (var prop of __getOwnPropSymbols$1(b)) {
      if (__propIsEnum$1.call(b, prop))
        __defNormalProp$1(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps$1 = (a, b) => __defProps$1(a, __getOwnPropDescs$1(b));
var __publicField = (obj, key, value) => __defNormalProp$1(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async$1 = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
const _LegislativeDataService = class _LegislativeDataService2 {
  constructor() {
    __publicField(this, "csvDataCache", null);
    __publicField(this, "requestCache", /* @__PURE__ */ new Map());
  }
  static getInstance() {
    if (!_LegislativeDataService2.instance) {
      _LegislativeDataService2.instance = new _LegislativeDataService2();
    }
    return _LegislativeDataService2.instance;
  }
  testBackendConnectivity() {
    return __async$1(this, null, function* () {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5e3);
        const baseUrl = getApiBaseUrl();
        const response = yield fetch(`${baseUrl}/health`, {
          method: "GET",
          signal: controller.signal,
          headers: { "Accept": "application/json" }
        });
        clearTimeout(timeoutId);
        if (response.ok) {
          return { available: true };
        } else {
          return { available: false, reason: `HTTP ${response.status}` };
        }
      } catch (error) {
        console.log(`Backend connectivity check failed: ${error instanceof Error ? error.message : "Unknown error"}`);
        return { available: false, reason: "Connection failed" };
      }
    });
  }
  getLocalCsvData() {
    return __async$1(this, null, function* () {
      if (this.csvDataCache && this.csvDataCache.length > 0) {
        console.log("Using cached real CSV data.");
        return { documents: this.csvDataCache, usingFallback: true };
      }
      try {
        console.log("Attempting to load real CSV legislative data...");
        const csvDocs = yield loadCSVLegislativeData();
        if (csvDocs && Array.isArray(csvDocs) && csvDocs.length > 0) {
          console.log(`Loaded ${csvDocs.length} real documents from CSV`);
          this.csvDataCache = csvDocs;
          return { documents: csvDocs, usingFallback: true };
        }
        throw new Error("CSV file was loaded but contained no documents or invalid data.");
      } catch (error) {
        console.error("Critical error: Failed to load or parse real CSV data.", error);
        console.error("🚨 NO MOCK FALLBACK: Academic integrity requires real data sources only");
        throw new Error(`Cannot load legislative data: ${error instanceof Error ? error.message : "Unknown CSV error"}. Real data source required.`);
      }
    });
  }
  fetchDocuments(filters) {
    return __async$1(this, null, function* () {
      const cacheKey = JSON.stringify(filters || {});
      if (this.requestCache.has(cacheKey)) {
        console.log("⚡ Request deduped: Using existing pending request");
        return this.requestCache.get(cacheKey);
      }
      const requestPromise = this._performFetch(filters);
      this.requestCache.set(cacheKey, requestPromise);
      console.log(`📊 Active requests: ${this.requestCache.size}`);
      requestPromise.finally(() => {
        this.requestCache.delete(cacheKey);
        console.log(`🧹 Cache cleanup - Active requests: ${this.requestCache.size}`);
      });
      return requestPromise;
    });
  }
  _performFetch(filters) {
    return __async$1(this, null, function* () {
      var _a, _b;
      try {
        console.log("🔬 Connecting to LexML Enhanced Research Engine...");
        const healthCheck = yield this.testBackendConnectivity();
        if (healthCheck.available) {
          console.log("✅ Backend connectivity confirmed, proceeding with enhanced search...");
          const params = this.buildQueryParams(filters);
          const enhancedParams = __spreadProps$1(__spreadValues$1({}, params), {
            sources: "lexml,camara,senado,planalto"
            // Prioritize LexML
          });
          console.log("🔍 API Search Parameters:", enhancedParams);
          const response = yield apiClient_default.get("/search", enhancedParams);
          console.log("📡 API Response Analysis:");
          console.log("  - Query:", response == null ? void 0 : response.query);
          console.log("  - Total Count:", response == null ? void 0 : response.total_count);
          console.log("  - Results Length:", ((_a = response == null ? void 0 : response.results) == null ? void 0 : _a.length) || 0);
          console.log("  - Sources:", response == null ? void 0 : response.sources);
          console.log("  - Enhanced Search:", response == null ? void 0 : response.enhanced_search);
          console.log("  - Filters Applied:", response == null ? void 0 : response.filters);
          console.log("  - Metadata:", response == null ? void 0 : response.metadata);
          if ((response == null ? void 0 : response.total_count) === 0) {
            console.warn("🚨 Backend API found 0 results for query:", response == null ? void 0 : response.query);
            console.log("🔧 This suggests the backend search needs investigation");
          }
          const documents = this.transformSearchResponse(response);
          if (documents.length === 0) {
            console.warn("🔄 Enhanced API returned no results, falling back to embedded real data");
            const localData = yield this.getLocalCsvData();
            return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
          }
          if ((_b = response.metadata) == null ? void 0 : _b.vocabulary_expansion) {
            console.log(`📚 Vocabulary enhanced search: '${response.metadata.vocabulary_expansion.original_term}' → ${response.metadata.vocabulary_expansion.expansion_count} terms`);
          }
          console.log(`✅ Successfully fetched ${documents.length} documents from LexML Enhanced API`);
          return { documents, usingFallback: false };
        } else {
          console.warn("⚠️ Backend not available, using embedded real data immediately");
          const localData = yield this.getLocalCsvData();
          return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
        }
      } catch (error) {
        console.warn("⚠️ Enhanced API fetch failed, attempting fallback to embedded real data:", error);
        try {
          const localData = yield this.getLocalCsvData();
          return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
        } catch (csvError) {
          console.error("❌ Both Enhanced API and embedded data sources failed:", { apiError: error, csvError });
          throw new Error("Unable to load legislative data from any real source (Enhanced API or embedded data). Please check data availability.");
        }
      }
    });
  }
  fetchDocumentById(id) {
    return __async$1(this, null, function* () {
      const allDocs = yield this.fetchDocuments();
      return allDocs.documents.find((doc) => doc.id === id) || null;
    });
  }
  searchDocuments(searchTerm) {
    return __async$1(this, null, function* () {
      const allDocs = yield this.fetchDocuments();
      const lowerSearchTerm = searchTerm.toLowerCase();
      return allDocs.documents.filter(
        (doc) => doc.title.toLowerCase().includes(lowerSearchTerm) || doc.summary.toLowerCase().includes(lowerSearchTerm) || doc.keywords && doc.keywords.some((keyword) => keyword.toLowerCase().includes(lowerSearchTerm))
      );
    });
  }
  filterLocalData(data, filters) {
    if (!filters) return data;
    return data.filter((doc) => {
      if (filters.searchTerm && !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.keywords.some((keyword) => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
        return false;
      }
      if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
        return false;
      }
      if (filters.states.length > 0 && doc.state && !filters.states.includes(doc.state)) {
        return false;
      }
      if (filters.municipalities.length > 0 && doc.municipality && !filters.municipalities.includes(doc.municipality)) {
        return false;
      }
      if (filters.chambers.length > 0 && doc.chamber && !filters.chambers.includes(doc.chamber)) {
        return false;
      }
      if (filters.dateFrom && new Date(doc.date) < filters.dateFrom) {
        return false;
      }
      if (filters.dateTo && new Date(doc.date) > filters.dateTo) {
        return false;
      }
      return true;
    });
  }
  buildQueryParams(filters) {
    const params = {};
    params.q = (filters == null ? void 0 : filters.searchTerm) || "transporte";
    if ((filters == null ? void 0 : filters.states) && filters.states.length > 0) {
      params.states = filters.states.join(",");
    }
    if (filters == null ? void 0 : filters.dateFrom) {
      params.start_date = this.formatDate(filters.dateFrom);
    }
    if (filters == null ? void 0 : filters.dateTo) {
      params.end_date = this.formatDate(filters.dateTo);
    }
    params.sources = "CAMARA,SENADO,PLANALTO";
    return params;
  }
  formatDate(date) {
    return date.toISOString().split("T")[0];
  }
  transformSearchResponse(response) {
    if (!response.results || !Array.isArray(response.results)) {
      return [];
    }
    return response.results.map((item) => this.transformProposition(item));
  }
  transformProposition(prop) {
    var _a, _b;
    const documentTypeMap = {
      "PL": "projeto_lei",
      "PLP": "projeto_lei",
      "PEC": "projeto_lei",
      "MPV": "medida_provisoria",
      "PLV": "projeto_lei",
      "PDL": "decreto",
      "PRC": "resolucao",
      "DECRETO": "decreto",
      "PORTARIA": "portaria",
      "RESOLUCAO": "resolucao",
      "INSTRUCAO_NORMATIVA": "instrucao_normativa",
      "LEI": "lei"
    };
    const statusMap = {
      "ACTIVE": "em_tramitacao",
      "APPROVED": "aprovado",
      "REJECTED": "rejeitado",
      "ARCHIVED": "arquivado",
      "WITHDRAWN": "arquivado",
      "PUBLISHED": "sancionado"
    };
    let state = "";
    if (prop.authors && Array.isArray(prop.authors) && prop.authors.length > 0) {
      state = prop.authors[0].state || "";
    }
    return {
      id: prop.id,
      title: prop.title,
      summary: prop.summary || "",
      type: documentTypeMap[prop.type] || "projeto_lei",
      date: prop.publication_date || prop.date || (/* @__PURE__ */ new Date()).toISOString(),
      keywords: prop.keywords || [],
      state,
      municipality: prop.municipality || "",
      url: prop.url || "",
      status: statusMap[prop.status] || "em_tramitacao",
      author: ((_b = (_a = prop.authors) == null ? void 0 : _a[0]) == null ? void 0 : _b.name) || "",
      chamber: prop.source === "CAMARA" ? "Câmara dos Deputados" : prop.source === "SENADO" ? "Senado Federal" : "",
      number: prop.number,
      source: prop.source,
      citation: prop.citation
    };
  }
};
__publicField(_LegislativeDataService, "instance");
let LegislativeDataService = _LegislativeDataService;
const legislativeDataService = LegislativeDataService.getInstance();
const useKeyboardNavigation = (onEscape, onEnter) => {
  const onEscapeRef = reactExports.useRef(onEscape);
  const onEnterRef = reactExports.useRef(onEnter);
  reactExports.useEffect(() => {
    onEscapeRef.current = onEscape;
    onEnterRef.current = onEnter;
  });
  const handleKeyDown = reactExports.useCallback((event) => {
    var _a, _b;
    switch (event.key) {
      case "Escape":
        (_a = onEscapeRef.current) == null ? void 0 : _a.call(onEscapeRef);
        break;
      case "Enter":
      case " ":
        event.preventDefault();
        (_b = onEnterRef.current) == null ? void 0 : _b.call(onEnterRef);
        break;
    }
  }, []);
  reactExports.useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
};
var __defProp = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
const OptimizedMap = reactExports.lazy(() => __vitePreload(() => import("./OptimizedMap-m10PmnUE.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0));
const TabbedSidebar = reactExports.lazy(() => __vitePreload(() => import("./TabbedSidebar-Ckn0YuF5.js"), true ? __vite__mapDeps([6,1,2,3,4,7]) : void 0));
const ExportPanel = reactExports.lazy(() => __vitePreload(() => import("./ExportPanel-BHM7wuwe.js"), true ? __vite__mapDeps([8,1,2,3,4,9,10,11]) : void 0));
const initialState = {
  sidebarOpen: true,
  exportPanelOpen: false,
  selectedState: void 0,
  selectedMunicipality: void 0,
  filters: {
    searchTerm: "",
    documentTypes: [],
    states: [],
    municipalities: [],
    chambers: [],
    keywords: [],
    dateFrom: void 0,
    dateTo: void 0
  }
};
const dashboardReducer = (state, action) => {
  switch (action.type) {
    case "TOGGLE_SIDEBAR":
      return __spreadProps(__spreadValues({}, state), { sidebarOpen: !state.sidebarOpen });
    case "SET_SIDEBAR_OPEN":
      return __spreadProps(__spreadValues({}, state), { sidebarOpen: action.payload });
    case "TOGGLE_EXPORT_PANEL":
      return __spreadProps(__spreadValues({}, state), { exportPanelOpen: !state.exportPanelOpen });
    case "SELECT_STATE":
      return __spreadProps(__spreadValues({}, state), { selectedState: action.payload, selectedMunicipality: void 0 });
    case "SELECT_MUNICIPALITY":
      return __spreadProps(__spreadValues({}, state), { selectedMunicipality: action.payload });
    case "CLEAR_SELECTION":
      return __spreadProps(__spreadValues({}, state), { selectedState: void 0, selectedMunicipality: void 0 });
    case "UPDATE_FILTERS":
      return __spreadProps(__spreadValues({}, state), { filters: action.payload });
    default:
      return state;
  }
};
const Dashboard = () => {
  const [state, dispatch] = reactExports.useReducer(dashboardReducer, initialState);
  const [documents, setDocuments] = reactExports.useState([]);
  const [isLoading, setIsLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const [usingFallbackData, setUsingFallbackData] = reactExports.useState(false);
  const { sidebarOpen, exportPanelOpen, selectedState, selectedMunicipality, filters } = state;
  const mainContentRef = reactExports.useRef(null);
  const debounceTimeoutRef = reactExports.useRef(null);
  const abortControllerRef = reactExports.useRef(null);
  useKeyboardNavigation();
  reactExports.useEffect(() => {
    const loadDocuments = () => __async(null, null, function* () {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      debounceTimeoutRef.current = setTimeout(() => __async(null, null, function* () {
        console.log("🎯 API Request: Debounced search triggered", { searchTerm: filters.searchTerm });
        setIsLoading(true);
        setError(null);
        try {
          abortControllerRef.current = new AbortController();
          const { documents: docs, usingFallback } = yield legislativeDataService.fetchDocuments(filters);
          if (docs.length === 0 && usingFallback) {
            setError("Could not load from API or CSV. Please check data sources.");
          }
          setDocuments(docs);
          setUsingFallbackData(usingFallback);
          console.log("📊 Request completed", { documentsFound: docs.length, usingFallback });
        } catch (err) {
          if (err instanceof Error && err.name === "AbortError") {
            console.log("⚡ Request cancelled - user continued typing");
            return;
          }
          const errorMessage = err instanceof Error ? err.message : "An unknown error occurred";
          setError(errorMessage);
          console.error("Error loading documents:", err);
        } finally {
          setIsLoading(false);
        }
      }), 500);
    });
    loadDocuments();
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [filters]);
  const handleLocationClick = reactExports.useCallback((type, id) => {
    dispatch({ type: type === "state" ? "SELECT_STATE" : "SELECT_MUNICIPALITY", payload: id });
  }, []);
  const handleClearSelection = reactExports.useCallback(() => dispatch({ type: "CLEAR_SELECTION" }), []);
  const onFiltersChange = reactExports.useCallback((newFilters) => dispatch({ type: "UPDATE_FILTERS", payload: newFilters }), []);
  const toggleSidebar = reactExports.useCallback(() => dispatch({ type: "TOGGLE_SIDEBAR" }), []);
  const toggleExportPanel = reactExports.useCallback(() => dispatch({ type: "TOGGLE_EXPORT_PANEL" }), []);
  const filteredDocuments = reactExports.useMemo(() => {
    if (!documents || !Array.isArray(documents)) {
      return [];
    }
    return documents.filter((doc) => {
      if (!doc) return false;
      if (selectedState && doc.state !== selectedState) return false;
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) return false;
      return true;
    });
  }, [documents, selectedState, selectedMunicipality]);
  const highlightedStates = reactExports.useMemo(() => {
    if (!filteredDocuments || !Array.isArray(filteredDocuments)) {
      return [];
    }
    return [...new Set(
      filteredDocuments.map((doc) => doc == null ? void 0 : doc.state).filter((state2) => Boolean(state2))
    )];
  }, [filteredDocuments]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "dashboard", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading sidebar..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      TabbedSidebar,
      {
        isOpen: sidebarOpen,
        onToggle: toggleSidebar,
        filters,
        onFiltersChange,
        documents: documents || [],
        selectedState,
        onClearSelection: handleClearSelection
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { id: "main-content", ref: mainContentRef, className: "main-content", tabIndex: -1, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "toolbar", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "toolbar-left", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { children: "Brazilian Transport Legislation Monitor" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "toolbar-subtitle", children: "Academic research platform for transport legislation analysis" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "toolbar-right", children: [
          isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading..." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stats", "aria-live": "polite", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-item", children: [
              "📄 ",
              filteredDocuments.length,
              " Docs"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-item", children: [
              "🗺️ ",
              highlightedStates.length,
              " States"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "export-btn", onClick: toggleExportPanel, "aria-controls": "export-panel", "aria-expanded": exportPanelOpen, children: "📊 Export" })
        ] })
      ] }),
      usingFallbackData && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "fallback-warning-banner", role: "alert", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Warning:" }),
        " Using local CSV data. API connection may have failed."
      ] }),
      error && !isLoading && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "dashboard-error", role: "alert", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Error Loading Data" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => window.location.reload(), children: "Try Again" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "map-wrapper", "aria-labelledby": "map-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "map-heading", className: "sr-only", children: "Interactive map" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading map..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          OptimizedMap,
          {
            selectedState,
            selectedMunicipality,
            documents: filteredDocuments || [],
            onLocationClick: handleLocationClick,
            highlightedLocations: highlightedStates || []
          }
        ) })
      ] }),
      (selectedState || selectedMunicipality) && /* @__PURE__ */ jsxRuntimeExports.jsx("aside", { className: "info-panel", role: "complementary", "aria-labelledby": "location-info-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "info-content", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: "location-info-heading", children: [
          selectedState && !selectedMunicipality && `State: ${selectedState}`,
          selectedMunicipality && `Municipality: ${selectedMunicipality}, ${selectedState}`
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          filteredDocuments.length,
          " documents found."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: handleClearSelection, className: "close-info", "aria-label": "Clear selection", children: "✕" })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading export panel..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExportPanel,
      {
        id: "export-panel",
        isOpen: exportPanelOpen,
        onClose: toggleExportPanel,
        documents: filteredDocuments || []
      }
    ) })
  ] });
};
var Dashboard_default = Dashboard;
export {
  Dashboard_default as default
};
