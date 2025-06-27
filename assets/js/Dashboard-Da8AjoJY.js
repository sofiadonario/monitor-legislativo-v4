const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/OptimizedMap-1is-_t1U.js","assets/js/index-BYGq6Ng0.js","assets/js/react-vendor-CSPBeBBz.js","assets/js/leaflet-vendor-BcXhkSxI.js","assets/css/index-CAI7Z5Wf.css","assets/css/OptimizedMap-D0H0UQSZ.css","assets/js/TabbedSidebar-JMZIN1ub.js","assets/css/TabbedSidebar-BUx3S1Ap.css","assets/js/ExportPanel-B4oO_6BS.js","assets/js/api-DW14Y_8v.js","assets/js/utils-Cs_fMHvp.js","assets/css/ExportPanel-rPKiQ0eQ.css","assets/js/AIResearchAssistant-DoAHUYra.js","assets/js/DocumentValidationPanel-BQBvTHRZ.js"])))=>i.map(i=>d[i]);
import { _ as __vitePreload, j as jsxRuntimeExports, L as LoadingSpinner } from "./index-BYGq6Ng0.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { A as API_CONFIG, g as getApiBaseUrl } from "./api-DW14Y_8v.js";
var __async$4 = (__this, __arguments, generator) => {
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
  return __async$4(this, null, function* () {
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
(() => __async$4(null, null, function* () {
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
var __defProp$3 = Object.defineProperty;
var __defProps$2 = Object.defineProperties;
var __getOwnPropDescs$2 = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols$3 = Object.getOwnPropertySymbols;
var __hasOwnProp$3 = Object.prototype.hasOwnProperty;
var __propIsEnum$3 = Object.prototype.propertyIsEnumerable;
var __defNormalProp$3 = (obj, key, value) => key in obj ? __defProp$3(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues$3 = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp$3.call(b, prop))
      __defNormalProp$3(a, prop, b[prop]);
  if (__getOwnPropSymbols$3)
    for (var prop of __getOwnPropSymbols$3(b)) {
      if (__propIsEnum$3.call(b, prop))
        __defNormalProp$3(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps$2 = (a, b) => __defProps$2(a, __getOwnPropDescs$2(b));
var __publicField$2 = (obj, key, value) => __defNormalProp$3(obj, typeof key !== "symbol" ? key + "" : key, value);
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
class ApiClient {
  constructor(config) {
    __publicField$2(this, "config");
    __publicField$2(this, "cache", /* @__PURE__ */ new Map());
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
    return __async$3(this, arguments, function* (url, options, retries = this.config.retries) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
      try {
        const response = yield fetch(url, __spreadProps$2(__spreadValues$3({}, options), {
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
    return __async$3(this, null, function* () {
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
    return __async$3(this, null, function* () {
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
var __defProp$2 = Object.defineProperty;
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
class MultiLayerCacheService {
  constructor(config = {}) {
    __publicField$1(this, "config");
    __publicField$1(this, "memoryCache");
    __publicField$1(this, "stats");
    __publicField$1(this, "compressionWorker");
    __publicField$1(this, "refreshQueue");
    __publicField$1(this, "prefetchQueue");
    this.config = __spreadValues$2({
      // Memory cache (fastest, smallest)
      memoryMaxSize: 50 * 1024 * 1024,
      // 50MB
      memoryTTL: 5 * 60 * 1e3,
      // 5 minutes
      // Session storage (per-session)
      sessionStorageMaxSize: 10 * 1024 * 1024,
      // 10MB
      sessionStorageTTL: 30 * 60 * 1e3,
      // 30 minutes
      // Local storage (persistent)
      localStorageMaxSize: 25 * 1024 * 1024,
      // 25MB
      localStorageTTL: 24 * 60 * 60 * 1e3,
      // 24 hours
      // Redis cache (server-side when available)
      redisEnabled: false,
      redisTTL: 60 * 60 * 1e3,
      // 1 hour
      redisMaxSize: 100 * 1024 * 1024,
      // 100MB
      // Performance features
      compressionEnabled: true,
      backgroundRefreshEnabled: true,
      prefetchEnabled: true
    }, config);
    this.memoryCache = /* @__PURE__ */ new Map();
    this.refreshQueue = /* @__PURE__ */ new Set();
    this.prefetchQueue = /* @__PURE__ */ new Set();
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      localStorageHits: 0,
      localStorageMisses: 0,
      sessionStorageHits: 0,
      sessionStorageMisses: 0,
      redisHits: 0,
      redisMisses: 0,
      totalRequests: 0,
      hitRate: 0,
      averageResponseTime: 0,
      cacheEfficiency: 0
    };
    this.initializeCompressionWorker();
    this.startMaintenanceTasks();
  }
  initializeCompressionWorker() {
    if (!this.config.compressionEnabled || typeof Worker === "undefined") {
      return;
    }
    try {
      const compressionCode = `
        self.onmessage = function(e) {
          const { action, data, id } = e.data;
          
          if (action === 'compress') {
            try {
              const compressed = LZString.compress(JSON.stringify(data));
              self.postMessage({ id, result: compressed, success: true });
            } catch (error) {
              self.postMessage({ id, error: error.message, success: false });
            }
          } else if (action === 'decompress') {
            try {
              const decompressed = JSON.parse(LZString.decompress(data));
              self.postMessage({ id, result: decompressed, success: true });
            } catch (error) {
              self.postMessage({ id, error: error.message, success: false });
            }
          }
        };
      `;
      const blob = new Blob([compressionCode], { type: "application/javascript" });
      this.compressionWorker = new Worker(URL.createObjectURL(blob));
    } catch (error) {
      console.warn("Failed to initialize compression worker:", error);
      this.config.compressionEnabled = false;
    }
  }
  startMaintenanceTasks() {
    setInterval(() => {
      this.cleanExpiredEntries();
    }, 5 * 60 * 1e3);
    setInterval(() => {
      this.updateStatistics();
    }, 60 * 1e3);
    if (this.config.backgroundRefreshEnabled) {
      setInterval(() => {
        this.processRefreshQueue();
      }, 30 * 1e3);
    }
    if (this.config.prefetchEnabled) {
      setInterval(() => {
        this.processPrefetchQueue();
      }, 10 * 1e3);
    }
  }
  /**
   * Get data from cache with multi-layer fallback
   */
  get(key, fallbackFn) {
    return __async$2(this, null, function* () {
      const startTime = Date.now();
      this.stats.totalRequests++;
      try {
        const memoryResult = yield this.getFromMemory(key);
        if (memoryResult !== null) {
          this.stats.memoryHits++;
          this.updateAccessStats(key, "memory", Date.now() - startTime);
          return memoryResult;
        }
        this.stats.memoryMisses++;
        const sessionResult = yield this.getFromSessionStorage(key);
        if (sessionResult !== null) {
          this.stats.sessionStorageHits++;
          yield this.setInMemory(key, sessionResult, this.config.memoryTTL);
          this.updateAccessStats(key, "session", Date.now() - startTime);
          return sessionResult;
        }
        this.stats.sessionStorageMisses++;
        const localResult = yield this.getFromLocalStorage(key);
        if (localResult !== null) {
          this.stats.localStorageHits++;
          yield this.setInMemory(key, localResult, this.config.memoryTTL);
          yield this.setInSessionStorage(key, localResult, this.config.sessionStorageTTL);
          this.updateAccessStats(key, "local", Date.now() - startTime);
          return localResult;
        }
        this.stats.localStorageMisses++;
        if (this.config.redisEnabled) {
          const redisResult = yield this.getFromRedis(key);
          if (redisResult !== null) {
            this.stats.redisHits++;
            yield this.setInMemory(key, redisResult, this.config.memoryTTL);
            yield this.setInSessionStorage(key, redisResult, this.config.sessionStorageTTL);
            yield this.setInLocalStorage(key, redisResult, this.config.localStorageTTL);
            this.updateAccessStats(key, "redis", Date.now() - startTime);
            return redisResult;
          }
          this.stats.redisMisses++;
        }
        if (fallbackFn) {
          const result = yield fallbackFn();
          if (result !== null) {
            yield this.set(key, result);
            this.scheduleBackgroundRefresh(key, fallbackFn);
          }
          return result;
        }
        return null;
      } catch (error) {
        console.error("Cache get error:", error);
        return fallbackFn ? yield fallbackFn() : null;
      }
    });
  }
  /**
   * Set data in all appropriate cache layers
   */
  set(key, data, customTTL) {
    return __async$2(this, null, function* () {
      try {
        const ttl = customTTL || this.config.memoryTTL;
        yield Promise.all([
          this.setInMemory(key, data, ttl),
          this.setInSessionStorage(key, data, this.config.sessionStorageTTL),
          this.setInLocalStorage(key, data, this.config.localStorageTTL),
          ...this.config.redisEnabled ? [this.setInRedis(key, data, this.config.redisTTL)] : []
        ]);
      } catch (error) {
        console.error("Cache set error:", error);
      }
    });
  }
  /**
   * Delete from all cache layers
   */
  delete(key) {
    return __async$2(this, null, function* () {
      try {
        yield Promise.all([
          this.deleteFromMemory(key),
          this.deleteFromSessionStorage(key),
          this.deleteFromLocalStorage(key),
          ...this.config.redisEnabled ? [this.deleteFromRedis(key)] : []
        ]);
      } catch (error) {
        console.error("Cache delete error:", error);
      }
    });
  }
  /**
   * Clear all cache layers
   */
  clear() {
    return __async$2(this, null, function* () {
      try {
        yield Promise.all([
          this.clearMemory(),
          this.clearSessionStorage(),
          this.clearLocalStorage(),
          ...this.config.redisEnabled ? [this.clearRedis()] : []
        ]);
        this.refreshQueue.clear();
        this.prefetchQueue.clear();
      } catch (error) {
        console.error("Cache clear error:", error);
      }
    });
  }
  // Memory cache operations
  getFromMemory(key) {
    return __async$2(this, null, function* () {
      const entry = this.memoryCache.get(key);
      if (!entry) return null;
      if (Date.now() > entry.timestamp + entry.ttl) {
        this.memoryCache.delete(key);
        return null;
      }
      entry.accessCount++;
      entry.lastAccessed = Date.now();
      return entry.data;
    });
  }
  setInMemory(key, data, ttl) {
    return __async$2(this, null, function* () {
      const size = this.calculateDataSize(data);
      yield this.ensureMemorySpace(size);
      const entry = {
        data,
        timestamp: Date.now(),
        ttl,
        accessCount: 1,
        lastAccessed: Date.now(),
        size,
        key
      };
      this.memoryCache.set(key, entry);
    });
  }
  deleteFromMemory(key) {
    return __async$2(this, null, function* () {
      this.memoryCache.delete(key);
    });
  }
  clearMemory() {
    return __async$2(this, null, function* () {
      this.memoryCache.clear();
    });
  }
  // Session storage operations
  getFromSessionStorage(key) {
    return __async$2(this, null, function* () {
      try {
        const item = sessionStorage.getItem(`mlc_${key}`);
        if (!item) return null;
        const entry = JSON.parse(item);
        if (Date.now() > entry.timestamp + entry.ttl) {
          sessionStorage.removeItem(`mlc_${key}`);
          return null;
        }
        return entry.compressed ? yield this.decompress(entry.data) : entry.data;
      } catch (error) {
        console.warn("Session storage get error:", error);
        return null;
      }
    });
  }
  setInSessionStorage(key, data, ttl) {
    return __async$2(this, null, function* () {
      try {
        const compressed = this.config.compressionEnabled ? yield this.compress(data) : data;
        const entry = {
          data: compressed,
          timestamp: Date.now(),
          ttl,
          accessCount: 1,
          lastAccessed: Date.now(),
          compressed: this.config.compressionEnabled,
          size: this.calculateDataSize(compressed),
          key
        };
        sessionStorage.setItem(`mlc_${key}`, JSON.stringify(entry));
      } catch (error) {
        console.warn("Session storage set error:", error);
      }
    });
  }
  deleteFromSessionStorage(key) {
    return __async$2(this, null, function* () {
      try {
        sessionStorage.removeItem(`mlc_${key}`);
      } catch (error) {
        console.warn("Session storage delete error:", error);
      }
    });
  }
  clearSessionStorage() {
    return __async$2(this, null, function* () {
      try {
        const keys = Object.keys(sessionStorage);
        keys.forEach((key) => {
          if (key.startsWith("mlc_")) {
            sessionStorage.removeItem(key);
          }
        });
      } catch (error) {
        console.warn("Session storage clear error:", error);
      }
    });
  }
  // Local storage operations
  getFromLocalStorage(key) {
    return __async$2(this, null, function* () {
      try {
        const item = localStorage.getItem(`mlc_${key}`);
        if (!item) return null;
        const entry = JSON.parse(item);
        if (Date.now() > entry.timestamp + entry.ttl) {
          localStorage.removeItem(`mlc_${key}`);
          return null;
        }
        return entry.compressed ? yield this.decompress(entry.data) : entry.data;
      } catch (error) {
        console.warn("Local storage get error:", error);
        return null;
      }
    });
  }
  setInLocalStorage(key, data, ttl) {
    return __async$2(this, null, function* () {
      try {
        const compressed = this.config.compressionEnabled ? yield this.compress(data) : data;
        const entry = {
          data: compressed,
          timestamp: Date.now(),
          ttl,
          accessCount: 1,
          lastAccessed: Date.now(),
          compressed: this.config.compressionEnabled,
          size: this.calculateDataSize(compressed),
          key
        };
        localStorage.setItem(`mlc_${key}`, JSON.stringify(entry));
      } catch (error) {
        console.warn("Local storage set error:", error);
      }
    });
  }
  deleteFromLocalStorage(key) {
    return __async$2(this, null, function* () {
      try {
        localStorage.removeItem(`mlc_${key}`);
      } catch (error) {
        console.warn("Local storage delete error:", error);
      }
    });
  }
  clearLocalStorage() {
    return __async$2(this, null, function* () {
      try {
        const keys = Object.keys(localStorage);
        keys.forEach((key) => {
          if (key.startsWith("mlc_")) {
            localStorage.removeItem(key);
          }
        });
      } catch (error) {
        console.warn("Local storage clear error:", error);
      }
    });
  }
  // Redis operations (placeholders for backend integration)
  getFromRedis(key) {
    return __async$2(this, null, function* () {
      return null;
    });
  }
  setInRedis(key, data, ttl) {
    return __async$2(this, null, function* () {
    });
  }
  deleteFromRedis(key) {
    return __async$2(this, null, function* () {
    });
  }
  clearRedis() {
    return __async$2(this, null, function* () {
    });
  }
  // Utility methods
  calculateDataSize(data) {
    return new Blob([JSON.stringify(data)]).size;
  }
  ensureMemorySpace(requiredSize) {
    return __async$2(this, null, function* () {
      const currentSize = Array.from(this.memoryCache.values()).reduce((total, entry) => total + entry.size, 0);
      if (currentSize + requiredSize <= this.config.memoryMaxSize) {
        return;
      }
      const entries = Array.from(this.memoryCache.entries()).sort(([, a], [, b]) => a.lastAccessed - b.lastAccessed);
      let freedSpace = 0;
      for (const [key, entry] of entries) {
        this.memoryCache.delete(key);
        freedSpace += entry.size;
        if (freedSpace >= requiredSize) {
          break;
        }
      }
    });
  }
  compress(data) {
    return __async$2(this, null, function* () {
      if (!this.config.compressionEnabled || !this.compressionWorker) {
        return data;
      }
      return new Promise((resolve) => {
        const id = Math.random().toString(36);
        const handler = (e) => {
          if (e.data.id === id) {
            this.compressionWorker.removeEventListener("message", handler);
            resolve(e.data.success ? e.data.result : data);
          }
        };
        this.compressionWorker.addEventListener("message", handler);
        this.compressionWorker.postMessage({ action: "compress", data, id });
        setTimeout(() => resolve(data), 1e3);
      });
    });
  }
  decompress(data) {
    return __async$2(this, null, function* () {
      if (!this.config.compressionEnabled || !this.compressionWorker) {
        return data;
      }
      return new Promise((resolve) => {
        const id = Math.random().toString(36);
        const handler = (e) => {
          if (e.data.id === id) {
            this.compressionWorker.removeEventListener("message", handler);
            resolve(e.data.success ? e.data.result : data);
          }
        };
        this.compressionWorker.addEventListener("message", handler);
        this.compressionWorker.postMessage({ action: "decompress", data, id });
        setTimeout(() => resolve(data), 1e3);
      });
    });
  }
  cleanExpiredEntries() {
    const now = Date.now();
    for (const [key, entry] of this.memoryCache.entries()) {
      if (now > entry.timestamp + entry.ttl) {
        this.memoryCache.delete(key);
      }
    }
  }
  updateStatistics() {
    const totalHits = this.stats.memoryHits + this.stats.sessionStorageHits + this.stats.localStorageHits + this.stats.redisHits;
    this.stats.hitRate = this.stats.totalRequests > 0 ? totalHits / this.stats.totalRequests * 100 : 0;
    this.stats.cacheEfficiency = this.calculateCacheEfficiency();
  }
  calculateCacheEfficiency() {
    const weightedHits = this.stats.memoryHits * 4 + this.stats.sessionStorageHits * 3 + this.stats.localStorageHits * 2 + this.stats.redisHits * 1;
    const maxPossibleScore = this.stats.totalRequests * 4;
    return maxPossibleScore > 0 ? weightedHits / maxPossibleScore * 100 : 0;
  }
  updateAccessStats(key, layer, responseTime) {
    this.stats.averageResponseTime = this.stats.averageResponseTime * 0.9 + responseTime * 0.1;
  }
  scheduleBackgroundRefresh(key, fallbackFn) {
    if (this.config.backgroundRefreshEnabled) {
      this.refreshQueue.add(key);
    }
  }
  processRefreshQueue() {
    return __async$2(this, null, function* () {
      const items = Array.from(this.refreshQueue).slice(0, 3);
      this.refreshQueue = new Set(Array.from(this.refreshQueue).slice(3));
      for (const key of items) {
      }
    });
  }
  processPrefetchQueue() {
    return __async$2(this, null, function* () {
      const items = Array.from(this.prefetchQueue).slice(0, 2);
      this.prefetchQueue = new Set(Array.from(this.prefetchQueue).slice(2));
      for (const key of items) {
      }
    });
  }
  /**
   * Get cache statistics
   */
  getStats() {
    this.updateStatistics();
    return __spreadValues$2({}, this.stats);
  }
  /**
   * Get cache size information
   */
  getCacheSizes() {
    const memorySize = Array.from(this.memoryCache.values()).reduce((total, entry) => total + entry.size, 0);
    return {
      memory: memorySize,
      session: 0,
      // Would calculate from sessionStorage
      local: 0,
      // Would calculate from localStorage  
      redis: 0
      // Would get from backend
    };
  }
  /**
   * Cleanup resources
   */
  dispose() {
    if (this.compressionWorker) {
      this.compressionWorker.terminate();
    }
    this.memoryCache.clear();
    this.refreshQueue.clear();
    this.prefetchQueue.clear();
  }
}
const multiLayerCache = new MultiLayerCacheService({
  compressionEnabled: true,
  backgroundRefreshEnabled: true,
  prefetchEnabled: true
});
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
      const cacheKey = _LegislativeDataService2.CACHE_KEYS.CSV_DATA;
      const cachedData = yield multiLayerCache.get(cacheKey);
      if (cachedData) {
        console.log("📦 Using multi-layer cached CSV data");
        return cachedData;
      }
      if (this.csvDataCache && this.csvDataCache.length > 0) {
        console.log("Using in-memory cached real CSV data.");
        const result = { documents: this.csvDataCache, usingFallback: true };
        yield multiLayerCache.set(cacheKey, result, 24 * 60 * 60 * 1e3);
        return result;
      }
      try {
        console.log("Attempting to load real CSV legislative data...");
        const csvDocs = yield loadCSVLegislativeData();
        if (csvDocs && Array.isArray(csvDocs) && csvDocs.length > 0) {
          console.log(`Loaded ${csvDocs.length} real documents from CSV`);
          this.csvDataCache = csvDocs;
          const result = { documents: csvDocs, usingFallback: true };
          yield multiLayerCache.set(cacheKey, result, 24 * 60 * 60 * 1e3);
          return result;
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
      const filterKey = JSON.stringify(filters || {});
      const cacheKey = `${_LegislativeDataService2.CACHE_KEYS.DOCUMENTS}_${filterKey}`;
      const cachedResult = yield multiLayerCache.get(
        cacheKey,
        () => __async$1(this, null, function* () {
          console.log("🔄 Cache miss - fetching fresh data");
          return yield this._performFetch(filters);
        })
      );
      if (cachedResult) {
        console.log("🎯 Cache hit - returning cached documents");
        return cachedResult;
      }
      if (this.requestCache.has(filterKey)) {
        console.log("⚡ Request deduped: Using existing pending request");
        return this.requestCache.get(filterKey);
      }
      const requestPromise = this._performFetch(filters);
      this.requestCache.set(filterKey, requestPromise);
      console.log(`📊 Active requests: ${this.requestCache.size}`);
      requestPromise.then((result) => __async$1(this, null, function* () {
        yield multiLayerCache.set(cacheKey, result, 10 * 60 * 1e3);
      })).finally(() => {
        this.requestCache.delete(filterKey);
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
      const cacheKey = `${_LegislativeDataService2.CACHE_KEYS.DOCUMENT_BY_ID}_${id}`;
      const cachedDoc = yield multiLayerCache.get(cacheKey);
      if (cachedDoc) {
        console.log(`🎯 Cache hit for document ID: ${id}`);
        return cachedDoc;
      }
      const allDocs = yield this.fetchDocuments();
      const document2 = allDocs.documents.find((doc) => doc.id === id) || null;
      if (document2) {
        yield multiLayerCache.set(cacheKey, document2, 30 * 60 * 1e3);
      }
      return document2;
    });
  }
  searchDocuments(searchTerm) {
    return __async$1(this, null, function* () {
      const cacheKey = `${_LegislativeDataService2.CACHE_KEYS.SEARCH_RESULTS}_${searchTerm.toLowerCase()}`;
      const cachedResults = yield multiLayerCache.get(cacheKey);
      if (cachedResults) {
        console.log(`🎯 Cache hit for search term: ${searchTerm}`);
        return cachedResults;
      }
      const allDocs = yield this.fetchDocuments();
      const lowerSearchTerm = searchTerm.toLowerCase();
      const results = allDocs.documents.filter(
        (doc) => doc.title.toLowerCase().includes(lowerSearchTerm) || doc.summary.toLowerCase().includes(lowerSearchTerm) || doc.keywords && doc.keywords.some((keyword) => keyword.toLowerCase().includes(lowerSearchTerm))
      );
      yield multiLayerCache.set(cacheKey, results, 15 * 60 * 1e3);
      return results;
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
  fetchCollectionStatus() {
    return __async$1(this, null, function* () {
      const cacheKey = _LegislativeDataService2.CACHE_KEYS.COLLECTION_STATUS;
      const cachedStatus = yield multiLayerCache.get(cacheKey);
      if (cachedStatus) {
        console.log("🎯 Cache hit for collection status");
        return cachedStatus;
      }
      try {
        const response = yield apiClient_default.get("/collections/recent");
        const results = this.transformCollectionLogs(response);
        yield multiLayerCache.set(cacheKey, results, 5 * 60 * 1e3);
        return results;
      } catch (error) {
        console.error("Failed to fetch collection status:", error);
        return [];
      }
    });
  }
  fetchLatestCollection() {
    return __async$1(this, null, function* () {
      const cacheKey = _LegislativeDataService2.CACHE_KEYS.LATEST_COLLECTION;
      const cachedLatest = yield multiLayerCache.get(cacheKey);
      if (cachedLatest !== null) {
        console.log("🎯 Cache hit for latest collection");
        return cachedLatest;
      }
      try {
        const response = yield apiClient_default.get("/collections/latest");
        let result = null;
        if (response && response.id) {
          result = this.transformCollectionLog(response);
        }
        yield multiLayerCache.set(cacheKey, result, 3 * 60 * 1e3);
        return result;
      } catch (error) {
        console.error("Failed to fetch latest collection:", error);
        return null;
      }
    });
  }
  transformCollectionLogs(response) {
    if (!response || !Array.isArray(response)) {
      return [];
    }
    return response.map((log) => this.transformCollectionLog(log));
  }
  transformCollectionLog(log) {
    return {
      id: log.id,
      searchTermId: log.search_term_id,
      searchTerm: log.search_term,
      status: log.status,
      recordsCollected: log.records_collected || 0,
      recordsNew: log.records_new || 0,
      recordsUpdated: log.records_updated || 0,
      recordsSkipped: log.records_skipped || 0,
      executionTimeMs: log.execution_time_ms || 0,
      errorMessage: log.error_message,
      startedAt: log.started_at,
      completedAt: log.completed_at,
      sourcesUsed: log.sources_used || []
    };
  }
  // Cache management methods
  invalidateCache(type) {
    return __async$1(this, null, function* () {
      switch (type) {
        case "documents":
          break;
        case "search":
          break;
        case "collections":
          break;
        case "all":
        default:
          yield multiLayerCache.clear();
          console.log("🧹 All caches cleared");
          return;
      }
      console.log(`🧹 Invalidating cache for type: ${type}`);
      yield multiLayerCache.clear();
    });
  }
  getCacheStats() {
    return __async$1(this, null, function* () {
      return multiLayerCache.getStats();
    });
  }
  getCacheSizes() {
    return __async$1(this, null, function* () {
      return multiLayerCache.getCacheSizes();
    });
  }
  // Force refresh specific data
  forceRefreshDocuments(filters) {
    return __async$1(this, null, function* () {
      const filterKey = JSON.stringify(filters || {});
      const cacheKey = `${_LegislativeDataService2.CACHE_KEYS.DOCUMENTS}_${filterKey}`;
      yield multiLayerCache.delete(cacheKey);
      return this.fetchDocuments(filters);
    });
  }
};
__publicField(_LegislativeDataService, "instance");
__publicField(_LegislativeDataService, "CACHE_KEYS", {
  DOCUMENTS: "legislative_docs",
  SEARCH_RESULTS: "search_results",
  DOCUMENT_BY_ID: "document_id",
  COLLECTION_STATUS: "collection_status",
  LATEST_COLLECTION: "latest_collection",
  CSV_DATA: "csv_data"
});
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
const OptimizedMap = reactExports.lazy(() => __vitePreload(() => import("./OptimizedMap-1is-_t1U.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0));
const TabbedSidebar = reactExports.lazy(() => __vitePreload(() => import("./TabbedSidebar-JMZIN1ub.js"), true ? __vite__mapDeps([6,1,2,3,4,7]) : void 0));
const ExportPanel = reactExports.lazy(() => __vitePreload(() => import("./ExportPanel-B4oO_6BS.js"), true ? __vite__mapDeps([8,1,2,3,4,9,10,11]) : void 0));
const AIResearchAssistant = reactExports.lazy(() => __vitePreload(() => import("./AIResearchAssistant-DoAHUYra.js"), true ? __vite__mapDeps([12,1,2,3,4,9]) : void 0));
const DocumentValidationPanel = reactExports.lazy(() => __vitePreload(() => import("./DocumentValidationPanel-BQBvTHRZ.js"), true ? __vite__mapDeps([13,1,2,3,4,9]) : void 0));
const initialState = {
  sidebarOpen: true,
  exportPanelOpen: false,
  aiAssistantOpen: false,
  validationPanelOpen: false,
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
  },
  selectedDocuments: []
};
const dashboardReducer = (state, action) => {
  switch (action.type) {
    case "TOGGLE_SIDEBAR":
      return __spreadProps(__spreadValues({}, state), { sidebarOpen: !state.sidebarOpen });
    case "SET_SIDEBAR_OPEN":
      return __spreadProps(__spreadValues({}, state), { sidebarOpen: action.payload });
    case "TOGGLE_EXPORT_PANEL":
      return __spreadProps(__spreadValues({}, state), { exportPanelOpen: !state.exportPanelOpen });
    case "TOGGLE_AI_ASSISTANT":
      return __spreadProps(__spreadValues({}, state), { aiAssistantOpen: !state.aiAssistantOpen });
    case "TOGGLE_VALIDATION_PANEL":
      return __spreadProps(__spreadValues({}, state), { validationPanelOpen: !state.validationPanelOpen });
    case "SELECT_STATE":
      return __spreadProps(__spreadValues({}, state), { selectedState: action.payload, selectedMunicipality: void 0 });
    case "SELECT_MUNICIPALITY":
      return __spreadProps(__spreadValues({}, state), { selectedMunicipality: action.payload });
    case "CLEAR_SELECTION":
      return __spreadProps(__spreadValues({}, state), { selectedState: void 0, selectedMunicipality: void 0 });
    case "UPDATE_FILTERS":
      return __spreadProps(__spreadValues({}, state), { filters: action.payload });
    case "SET_SELECTED_DOCUMENTS":
      return __spreadProps(__spreadValues({}, state), { selectedDocuments: action.payload });
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
  const { sidebarOpen, exportPanelOpen, aiAssistantOpen, validationPanelOpen, selectedState, selectedMunicipality, filters, selectedDocuments } = state;
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
  const toggleAIAssistant = reactExports.useCallback(() => dispatch({ type: "TOGGLE_AI_ASSISTANT" }), []);
  const toggleValidationPanel = reactExports.useCallback(() => dispatch({ type: "TOGGLE_VALIDATION_PANEL" }), []);
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "ai-btn", onClick: toggleAIAssistant, "aria-controls": "ai-assistant", "aria-expanded": aiAssistantOpen, children: "🤖 AI Assistant" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "validation-btn", onClick: toggleValidationPanel, "aria-controls": "validation-panel", "aria-expanded": validationPanelOpen, children: "🛡️ Validate" }),
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
    ) }),
    aiAssistantOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading AI assistant..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      AIResearchAssistant,
      {
        selectedDocuments,
        onDocumentAnalyzed: (analysis) => console.log("Document analyzed:", analysis),
        className: "ai-assistant-panel"
      }
    ) }),
    validationPanelOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading validation panel..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      DocumentValidationPanel,
      {
        documents: selectedDocuments,
        onValidationComplete: (results) => console.log("Validation complete:", results),
        className: "validation-panel"
      }
    ) })
  ] });
};
var Dashboard_default = Dashboard;
const Dashboard$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: Dashboard_default
}, Symbol.toStringTag, { value: "Module" }));
export {
  Dashboard$1 as D,
  apiClient_default as a
};
