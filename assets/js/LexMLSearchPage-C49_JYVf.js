import { j as jsxRuntimeExports } from "./index-CREcncgK.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { g as getApiBaseUrl } from "./api-CK1EtbNt.js";
import "./react-vendor-CSPBeBBz.js";
var __defProp$2 = Object.defineProperty;
var __defNormalProp$2 = (obj, key, value) => key in obj ? __defProp$2(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField$1 = (obj, key, value) => __defNormalProp$2(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async$6 = (__this, __arguments, generator) => {
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
class CacheService {
  constructor() {
    __publicField$1(this, "memoryCache", /* @__PURE__ */ new Map());
    __publicField$1(this, "stats", {
      hits: 0,
      misses: 0,
      evictions: 0,
      totalRequests: 0
    });
    __publicField$1(this, "config", {
      // TTLs in milliseconds
      searchResults: 5 * 60 * 1e3,
      // 5 minutes
      documentContent: 30 * 60 * 1e3,
      // 30 minutes
      suggestions: 10 * 60 * 1e3,
      // 10 minutes
      healthStatus: 2 * 60 * 1e3,
      // 2 minutes
      crossReferences: 60 * 60 * 1e3,
      // 1 hour
      relatedDocuments: 20 * 60 * 1e3,
      // 20 minutes
      // Memory limits
      maxMemoryItems: 1e3,
      maxItemSizeBytes: 1024 * 1024,
      // 1MB per item
      // Persistence
      persistToLocalStorage: true,
      localStoragePrefix: "lexmlCache_"
    });
    this.loadFromLocalStorage();
    setInterval(() => this.cleanup(), 6e4);
    if (typeof window !== "undefined") {
      window.addEventListener("storage", this.handleStorageEvent.bind(this));
    }
  }
  /**
   * Get item from cache with automatic expiration check
   */
  get(key) {
    this.stats.totalRequests++;
    const item = this.memoryCache.get(key);
    if (!item) {
      this.stats.misses++;
      return this.getFromLocalStorage(key);
    }
    if (Date.now() > item.expiresAt) {
      this.memoryCache.delete(key);
      this.removeFromLocalStorage(key);
      this.stats.misses++;
      return null;
    }
    item.accessCount++;
    item.lastAccessed = Date.now();
    this.stats.hits++;
    return item.data;
  }
  /**
   * Set item in cache with TTL
   */
  set(key, data, ttlMs) {
    const now = Date.now();
    const ttl = ttlMs || this.getTTLForKey(key);
    const item = {
      data,
      timestamp: now,
      expiresAt: now + ttl,
      accessCount: 0,
      lastAccessed: now
    };
    if (this.memoryCache.size >= this.config.maxMemoryItems) {
      this.evictLeastRecentlyUsed();
    }
    const itemSize = this.estimateSize(data);
    if (itemSize > this.config.maxItemSizeBytes) {
      console.warn(`Cache item too large (${itemSize} bytes), skipping cache for key: ${key}`);
      return;
    }
    this.memoryCache.set(key, item);
    if (this.config.persistToLocalStorage) {
      this.saveToLocalStorage(key, item);
    }
  }
  /**
   * Remove item from all cache layers
   */
  delete(key) {
    this.memoryCache.delete(key);
    this.removeFromLocalStorage(key);
  }
  /**
   * Clear entire cache
   */
  clear() {
    this.memoryCache.clear();
    this.clearLocalStorage();
    this.stats = { hits: 0, misses: 0, evictions: 0, totalRequests: 0 };
  }
  /**
   * Get cache statistics
   */
  getStats() {
    const hitRate = this.stats.totalRequests > 0 ? this.stats.hits / this.stats.totalRequests * 100 : 0;
    const missRate = 100 - hitRate;
    return {
      totalItems: this.memoryCache.size,
      memoryUsage: this.estimateMemoryUsage(),
      hitRate: Number(hitRate.toFixed(2)),
      missRate: Number(missRate.toFixed(2)),
      evictions: this.stats.evictions
    };
  }
  /**
   * Create cache key for search requests
   */
  createSearchKey(query, filters, startRecord, maxRecords) {
    const filterStr = JSON.stringify(filters || {});
    return `search:${query}:${filterStr}:${startRecord}:${maxRecords}`;
  }
  /**
   * Create cache key for document content
   */
  createDocumentKey(urn) {
    return `document:${urn}`;
  }
  /**
   * Create cache key for suggestions
   */
  createSuggestionsKey(term, field) {
    return field ? `suggestions:${field}:${term}` : `suggestions:${term}`;
  }
  /**
   * Create cache key for cross-references
   */
  createCrossReferencesKey(urn) {
    return `crossref:${urn}`;
  }
  /**
   * Create cache key for related documents
   */
  createRelatedDocumentsKey(urn, maxResults) {
    return `related:${urn}:${maxResults}`;
  }
  /**
   * Prefetch and cache common queries
   */
  prefetchCommonQueries() {
    return __async$6(this, null, function* () {
      const commonQueries = [
        "transporte",
        "mobilidade urbana",
        "trânsito",
        "transporte público"
      ];
      commonQueries.forEach((query) => {
        const key = this.createSearchKey(query, {}, 1, 50);
        this.set(key, { prefetched: true, query }, this.config.searchResults);
      });
    });
  }
  // Private methods
  getTTLForKey(key) {
    if (key.startsWith("search:")) return this.config.searchResults;
    if (key.startsWith("document:")) return this.config.documentContent;
    if (key.startsWith("suggestions:")) return this.config.suggestions;
    if (key.startsWith("health:")) return this.config.healthStatus;
    if (key.startsWith("crossref:")) return this.config.crossReferences;
    if (key.startsWith("related:")) return this.config.relatedDocuments;
    return this.config.searchResults;
  }
  evictLeastRecentlyUsed() {
    let oldestKey = "";
    let oldestTime = Date.now();
    for (const [key, item] of this.memoryCache.entries()) {
      if (item.lastAccessed < oldestTime) {
        oldestTime = item.lastAccessed;
        oldestKey = key;
      }
    }
    if (oldestKey) {
      this.memoryCache.delete(oldestKey);
      this.removeFromLocalStorage(oldestKey);
      this.stats.evictions++;
    }
  }
  cleanup() {
    const now = Date.now();
    const keysToDelete = [];
    for (const [key, item] of this.memoryCache.entries()) {
      if (now > item.expiresAt) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach((key) => {
      this.memoryCache.delete(key);
      this.removeFromLocalStorage(key);
    });
  }
  estimateSize(data) {
    return JSON.stringify(data).length * 2;
  }
  estimateMemoryUsage() {
    let totalSize = 0;
    for (const [key, item] of this.memoryCache.entries()) {
      totalSize += this.estimateSize(key) + this.estimateSize(item);
    }
    return totalSize;
  }
  // LocalStorage persistence methods
  saveToLocalStorage(key, item) {
    if (typeof window === "undefined") return;
    try {
      const storageKey = this.config.localStoragePrefix + key;
      localStorage.setItem(storageKey, JSON.stringify(item));
    } catch (error) {
      console.warn("Failed to save to localStorage:", error);
    }
  }
  getFromLocalStorage(key) {
    if (typeof window === "undefined") return null;
    try {
      const storageKey = this.config.localStoragePrefix + key;
      const stored = localStorage.getItem(storageKey);
      if (!stored) return null;
      const item = JSON.parse(stored);
      if (Date.now() > item.expiresAt) {
        localStorage.removeItem(storageKey);
        return null;
      }
      this.memoryCache.set(key, item);
      this.stats.hits++;
      return item.data;
    } catch (error) {
      console.warn("Failed to read from localStorage:", error);
      return null;
    }
  }
  removeFromLocalStorage(key) {
    if (typeof window === "undefined") return;
    try {
      const storageKey = this.config.localStoragePrefix + key;
      localStorage.removeItem(storageKey);
    } catch (error) {
      console.warn("Failed to remove from localStorage:", error);
    }
  }
  loadFromLocalStorage() {
    if (typeof window === "undefined") return;
    try {
      const prefix = this.config.localStoragePrefix;
      for (let i = 0; i < localStorage.length; i++) {
        const fullKey = localStorage.key(i);
        if (!fullKey || !fullKey.startsWith(prefix)) continue;
        const key = fullKey.substring(prefix.length);
        const stored = localStorage.getItem(fullKey);
        if (stored) {
          const item = JSON.parse(stored);
          if (Date.now() <= item.expiresAt) {
            this.memoryCache.set(key, item);
          } else {
            localStorage.removeItem(fullKey);
          }
        }
      }
    } catch (error) {
      console.warn("Failed to load from localStorage:", error);
    }
  }
  clearLocalStorage() {
    if (typeof window === "undefined") return;
    try {
      const prefix = this.config.localStoragePrefix;
      const keysToRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach((key) => localStorage.removeItem(key));
    } catch (error) {
      console.warn("Failed to clear localStorage:", error);
    }
  }
  handleStorageEvent(event) {
    if (!event.key || !event.key.startsWith(this.config.localStoragePrefix)) return;
    const key = event.key.substring(this.config.localStoragePrefix.length);
    if (event.newValue === null) {
      this.memoryCache.delete(key);
    } else {
      try {
        const item = JSON.parse(event.newValue);
        if (Date.now() <= item.expiresAt) {
          this.memoryCache.set(key, item);
        }
      } catch (error) {
        console.warn("Failed to sync storage event:", error);
      }
    }
  }
}
const cacheService = new CacheService();
const getCachedSearchResults = (query, filters, startRecord, maxRecords) => {
  const key = cacheService.createSearchKey(query, filters, startRecord, maxRecords);
  return cacheService.get(key);
};
const setCachedSearchResults = (query, filters, startRecord, maxRecords, data) => {
  const key = cacheService.createSearchKey(query, filters, startRecord, maxRecords);
  cacheService.set(key, data);
};
const getCachedDocument = (urn) => {
  const key = cacheService.createDocumentKey(urn);
  return cacheService.get(key);
};
const setCachedDocument = (urn, data) => {
  const key = cacheService.createDocumentKey(urn);
  cacheService.set(key, data);
};
const getCachedSuggestions = (term, field) => {
  const key = cacheService.createSuggestionsKey(term, field);
  return cacheService.get(key);
};
const setCachedSuggestions = (term, data, field) => {
  const key = cacheService.createSuggestionsKey(term, field);
  cacheService.set(key, data);
};
var __defProp$1 = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
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
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
var __publicField = (obj, key, value) => __defNormalProp$1(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async$5 = (__this, __arguments, generator) => {
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
class LexMLAPIService {
  // 10 seconds
  constructor(baseURL = "") {
    __publicField(this, "baseURL");
    __publicField(this, "defaultTimeout", 1e4);
    this.baseURL = baseURL || getApiBaseUrl();
    console.log(`🔧 LexMLAPIService initialized with baseURL: ${this.baseURL}`);
  }
  /**
   * Search LexML documents with live API integration and caching
   */
  searchDocuments(request) {
    return __async$5(this, null, function* () {
      var _a, _b, _c;
      const query = request.query || request.cql_query || "";
      const startRecord = request.start_record || 1;
      const maxRecords = request.max_records || 50;
      const cachedResult = getCachedSearchResults(query, request.filters, startRecord, maxRecords);
      if (cachedResult) {
        return __spreadProps(__spreadValues$1({}, cachedResult), {
          cache_hit: true,
          search_time_ms: 0
          // Cached response is instant
        });
      }
      const searchParams = new URLSearchParams();
      if (request.query) {
        searchParams.append("q", request.query);
      }
      if (request.cql_query) {
        searchParams.append("cql", request.cql_query);
      }
      if (request.filters) {
        const filters = request.filters;
        if (filters.tipoDocumento.length > 0) {
          filters.tipoDocumento.forEach((tipo) => {
            searchParams.append("tipo_documento", tipo);
          });
        }
        if (filters.autoridade.length > 0) {
          filters.autoridade.forEach((auth) => {
            searchParams.append("autoridade", auth);
          });
        }
        if (filters.localidade.length > 0) {
          filters.localidade.forEach((loc) => {
            searchParams.append("localidade", loc);
          });
        }
        if (filters.date_from) {
          searchParams.append("date_from", filters.date_from);
        }
        if (filters.date_to) {
          searchParams.append("date_to", filters.date_to);
        }
        if (filters.subject.length > 0) {
          filters.subject.forEach((subj) => {
            searchParams.append("subject", subj);
          });
        }
      }
      if (request.start_record) {
        searchParams.append("start_record", request.start_record.toString());
      }
      if (request.max_records) {
        searchParams.append("max_records", request.max_records.toString());
      }
      if (request.include_content !== void 0) {
        searchParams.append("include_content", request.include_content.toString());
      }
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.defaultTimeout);
        const fullUrl = `${this.baseURL}/api/lexml/search?${searchParams}`;
        console.log("🌐 Making API request to:", fullUrl);
        const response = yield fetch(fullUrl, {
          method: "GET",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
          },
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        console.log("📡 Response received:", {
          status: response.status,
          statusText: response.statusText,
          ok: response.ok,
          headers: Object.fromEntries(response.headers.entries())
        });
        if (!response.ok) {
          throw new Error(`Search failed: ${response.status} ${response.statusText}`);
        }
        const result = yield response.json();
        console.log("🔍 Raw API Response:", {
          url: `${this.baseURL}/api/lexml/search?${searchParams}`,
          status: response.status,
          result,
          total_found: result.total_found,
          documents_length: (_a = result.documents) == null ? void 0 : _a.length,
          keys: Object.keys(result)
        });
        const transformedDocuments = (result.documents || []).map((doc) => {
          var _a2, _b2, _c2, _d, _e, _f, _g;
          return {
            metadata: {
              urn: doc.urn,
              title: doc.title,
              description: doc.description || "",
              date: ((_a2 = doc.metadata) == null ? void 0 : _a2.date) || (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
              tipoDocumento: ((_b2 = doc.metadata) == null ? void 0 : _b2.type) || "Lei",
              autoridade: ((_d = (_c2 = doc.metadata) == null ? void 0 : _c2.chamber) == null ? void 0 : _d.toLowerCase()) || "federal",
              localidade: ((_e = doc.metadata) == null ? void 0 : _e.state) || "BR",
              subject: ((_f = doc.metadata) == null ? void 0 : _f.keywords) || [],
              identifier: doc.urn,
              source_url: doc.url
            },
            full_text: doc.full_text,
            structure: doc.structure,
            last_modified: ((_g = doc.metadata) == null ? void 0 : _g.date) || (/* @__PURE__ */ new Date()).toISOString(),
            data_source: result.data_source || "csv-fallback",
            cache_key: doc.urn
          };
        });
        const enhancedResult = {
          documents: transformedDocuments,
          total_found: result.total_found || ((_b = result.documents) == null ? void 0 : _b.length) || 0,
          start_record: result.start_record || 1,
          records_returned: transformedDocuments.length,
          next_start_record: result.next_start_record,
          search_time_ms: result.search_time_ms || 0,
          data_source: result.data_source || "csv-fallback",
          cache_hit: result.cache_hit || false,
          api_status: result.api_status || "unknown"
        };
        console.log("🔄 Transformed Response:", {
          originalCount: ((_c = result.documents) == null ? void 0 : _c.length) || 0,
          transformedCount: transformedDocuments.length,
          sampleDocument: transformedDocuments[0] || null
        });
        setCachedSearchResults(query, request.filters, startRecord, maxRecords, enhancedResult);
        return enhancedResult;
      } catch (error) {
        console.error("🚨 LexML search error details:", {
          error,
          message: error instanceof Error ? error.message : "Unknown error",
          stack: error instanceof Error ? error.stack : "No stack trace",
          name: error instanceof Error ? error.name : "Unknown error type",
          baseURL: this.baseURL,
          searchParams: searchParams.toString()
        });
        return {
          documents: [],
          total_found: 0,
          start_record: request.start_record || 1,
          records_returned: 0,
          search_time_ms: 0,
          data_source: "csv-fallback",
          cache_hit: false,
          api_status: "error"
        };
      }
    });
  }
  /**
   * Get search suggestions for auto-complete with LexML taxonomy integration and caching
   */
  getSuggestions(term, maxSuggestions = 10) {
    return __async$5(this, null, function* () {
      if (term.length < 2) {
        return [];
      }
      const cachedSuggestions = getCachedSuggestions(term);
      if (cachedSuggestions) {
        return cachedSuggestions.slice(0, maxSuggestions);
      }
      try {
        const response = yield fetch(
          `${this.baseURL}/api/lexml/suggest?term=${encodeURIComponent(term)}&max_suggestions=${maxSuggestions}`,
          {
            method: "GET",
            headers: {
              "Accept": "application/json"
            }
          }
        );
        if (!response.ok) {
          throw new Error(`Suggestions failed: ${response.status}`);
        }
        const result = yield response.json();
        const suggestions = result.suggestions || [];
        setCachedSuggestions(term, suggestions);
        return suggestions;
      } catch (error) {
        console.error("Suggestions error:", error);
        return this.getLocalTaxonomySuggestions(term, maxSuggestions);
      }
    });
  }
  /**
   * Get taxonomy-based suggestions using local LexML vocabulary
   */
  getLocalTaxonomySuggestions(term, maxSuggestions = 10) {
    const lowercaseTerm = term.toLowerCase();
    const taxonomyTerms = {
      // Document Types
      "lei": { category: "Document Type", description: "Federal, state, or municipal laws" },
      "decreto": { category: "Document Type", description: "Executive decrees and regulations" },
      "portaria": { category: "Document Type", description: "Administrative ordinances" },
      "resolução": { category: "Document Type", description: "Administrative resolutions" },
      "medida provisória": { category: "Document Type", description: "Provisional measures (federal)" },
      "instrução normativa": { category: "Document Type", description: "Normative instructions" },
      // Transport-specific terms
      "transporte": { category: "Subject", description: "General transportation legislation" },
      "transporte urbano": { category: "Subject", description: "Urban transportation systems" },
      "mobilidade urbana": { category: "Subject", description: "Urban mobility and accessibility" },
      "trânsito": { category: "Subject", description: "Traffic and transit regulations" },
      "infraestrutura": { category: "Subject", description: "Transportation infrastructure" },
      "logística": { category: "Subject", description: "Logistics and cargo transport" },
      "transporte público": { category: "Subject", description: "Public transportation systems" },
      "transporte coletivo": { category: "Subject", description: "Collective transportation" },
      "metrô": { category: "Subject", description: "Subway and metro systems" },
      "ônibus": { category: "Subject", description: "Bus transportation" },
      "brt": { category: "Subject", description: "Bus Rapid Transit systems" },
      "vlt": { category: "Subject", description: "Light Rail Transit (VLT)" },
      "trem": { category: "Subject", description: "Train and railway transport" },
      "aeroporto": { category: "Subject", description: "Airport infrastructure and regulation" },
      "porto": { category: "Subject", description: "Port and maritime transport" },
      "rodovia": { category: "Subject", description: "Highway and road infrastructure" },
      "ciclovia": { category: "Subject", description: "Bicycle lanes and cycling infrastructure" },
      "acessibilidade": { category: "Subject", description: "Transportation accessibility" },
      "sustentabilidade": { category: "Subject", description: "Sustainable transportation" },
      // Authorities
      "federal": { category: "Authority", description: "Federal government legislation" },
      "estadual": { category: "Authority", description: "State government legislation" },
      "municipal": { category: "Authority", description: "Municipal government legislation" },
      "distrital": { category: "Authority", description: "Federal District legislation" },
      // Common locations
      "são paulo": { category: "Location", description: "São Paulo state or city" },
      "rio de janeiro": { category: "Location", description: "Rio de Janeiro state or city" },
      "minas gerais": { category: "Location", description: "Minas Gerais state" },
      "brasília": { category: "Location", description: "Federal District (Brasília)" },
      "paraná": { category: "Location", description: "Paraná state" },
      "rio grande do sul": { category: "Location", description: "Rio Grande do Sul state" },
      "bahia": { category: "Location", description: "Bahia state" },
      "santa catarina": { category: "Location", description: "Santa Catarina state" },
      // Legal concepts
      "regulamentação": { category: "Legal Concept", description: "Regulatory provisions" },
      "licenciamento": { category: "Legal Concept", description: "Licensing and permits" },
      "fiscalização": { category: "Legal Concept", description: "Inspection and enforcement" },
      "concessão": { category: "Legal Concept", description: "Concessions and franchises" },
      "licitação": { category: "Legal Concept", description: "Public procurement and bidding" },
      "tarifa": { category: "Legal Concept", description: "Tariffs and pricing" },
      "subsídio": { category: "Legal Concept", description: "Subsidies and financial support" }
    };
    const matches = [];
    for (const [termKey, termData] of Object.entries(taxonomyTerms)) {
      if (termKey.toLowerCase().includes(lowercaseTerm) || termData.description.toLowerCase().includes(lowercaseTerm)) {
        matches.push({
          text: termKey,
          category: termData.category,
          description: termData.description,
          count: Math.floor(Math.random() * 100) + 1
          // Simulated count
        });
      }
    }
    matches.sort((a, b) => {
      const aExact = a.text.toLowerCase() === lowercaseTerm;
      const bExact = b.text.toLowerCase() === lowercaseTerm;
      const aStarts = a.text.toLowerCase().startsWith(lowercaseTerm);
      const bStarts = b.text.toLowerCase().startsWith(lowercaseTerm);
      if (aExact && !bExact) return -1;
      if (!aExact && bExact) return 1;
      if (aStarts && !bStarts) return -1;
      if (!aStarts && bStarts) return 1;
      return b.count - a.count;
    });
    return matches.slice(0, maxSuggestions);
  }
  /**
   * Get field-specific suggestions based on LexML schema
   */
  getFieldSuggestions(field, term, maxSuggestions = 10) {
    return __async$5(this, null, function* () {
      const lowercaseTerm = term.toLowerCase();
      switch (field) {
        case "tipoDocumento":
          return [
            { text: "Lei", category: "Document Type", description: "Laws and statutes", count: 1500 },
            { text: "Decreto", category: "Document Type", description: "Executive decrees", count: 800 },
            { text: "Portaria", category: "Document Type", description: "Administrative ordinances", count: 600 },
            { text: "Resolução", category: "Document Type", description: "Administrative resolutions", count: 400 },
            { text: "Medida Provisória", category: "Document Type", description: "Provisional measures", count: 200 },
            { text: "Instrução Normativa", category: "Document Type", description: "Normative instructions", count: 300 }
          ].filter((item) => item.text.toLowerCase().includes(lowercaseTerm)).slice(0, maxSuggestions);
        case "autoridade":
          return [
            { text: "federal", category: "Authority", description: "Federal government", count: 2e3 },
            { text: "estadual", category: "Authority", description: "State governments", count: 1500 },
            { text: "municipal", category: "Authority", description: "Municipal governments", count: 1200 },
            { text: "distrital", category: "Authority", description: "Federal District", count: 300 }
          ].filter((item) => item.text.toLowerCase().includes(lowercaseTerm)).slice(0, maxSuggestions);
        case "localidade":
          const locations = [
            "São Paulo",
            "Rio de Janeiro",
            "Minas Gerais",
            "Paraná",
            "Rio Grande do Sul",
            "Bahia",
            "Santa Catarina",
            "Distrito Federal",
            "Goiás",
            "Espírito Santo",
            "Ceará",
            "Pernambuco",
            "Pará",
            "Maranhão",
            "Amazonas"
          ];
          return locations.filter((loc) => loc.toLowerCase().includes(lowercaseTerm)).map((loc) => ({
            text: loc,
            category: "Location",
            description: `Legislation from ${loc}`,
            count: Math.floor(Math.random() * 500) + 50
          })).slice(0, maxSuggestions);
        case "subject":
          const subjects = [
            "transporte",
            "transporte urbano",
            "mobilidade urbana",
            "trânsito",
            "infraestrutura",
            "logística",
            "transporte público",
            "metrô",
            "ônibus",
            "brt",
            "vlt",
            "trem",
            "aeroporto",
            "porto",
            "rodovia",
            "ciclovia",
            "acessibilidade",
            "sustentabilidade"
          ];
          return subjects.filter((subj) => subj.toLowerCase().includes(lowercaseTerm)).map((subj) => ({
            text: subj,
            category: "Subject",
            description: `Documents about ${subj}`,
            count: Math.floor(Math.random() * 300) + 20
          })).slice(0, maxSuggestions);
        default:
          return this.getLocalTaxonomySuggestions(term, maxSuggestions);
      }
    });
  }
  /**
   * Get full document content by URN with caching
   */
  getDocumentContent(urn) {
    return __async$5(this, null, function* () {
      const cachedDocument = getCachedDocument(urn);
      if (cachedDocument) {
        return __spreadProps(__spreadValues$1({}, cachedDocument), {
          cached: true
        });
      }
      try {
        const response = yield fetch(
          `${this.baseURL}/api/lexml/document/${encodeURIComponent(urn)}`,
          {
            method: "GET",
            headers: {
              "Accept": "application/json"
            }
          }
        );
        if (!response.ok) {
          if (response.status === 404) {
            return null;
          }
          throw new Error(`Document retrieval failed: ${response.status}`);
        }
        const document2 = yield response.json();
        setCachedDocument(urn, document2);
        return document2;
      } catch (error) {
        console.error("Document content error:", error);
        return null;
      }
    });
  }
  /**
   * Get API health status
   */
  getHealthStatus() {
    return __async$5(this, null, function* () {
      try {
        const response = yield fetch(`${this.baseURL}/api/lexml/health`, {
          method: "GET",
          headers: {
            "Accept": "application/json"
          }
        });
        if (!response.ok) {
          throw new Error(`Health check failed: ${response.status}`);
        }
        return yield response.json();
      } catch (error) {
        console.error("Health check error:", error);
        return null;
      }
    });
  }
  /**
   * Parse and validate CQL query
   */
  parseCQLQuery(query) {
    return __async$5(this, null, function* () {
      try {
        const response = yield fetch(`${this.baseURL}/api/lexml/cql/parse`, {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: `query=${encodeURIComponent(query)}`
        });
        if (response.ok) {
          return { isValid: true };
        } else {
          const error = yield response.json();
          return { isValid: false, error: error.detail };
        }
      } catch (error) {
        console.error("CQL parsing error:", error);
        return { isValid: false, error: "Network error" };
      }
    });
  }
  /**
   * Get common CQL patterns for legal research
   */
  getCommonPatterns() {
    return __async$5(this, null, function* () {
      try {
        const response = yield fetch(`${this.baseURL}/api/lexml/patterns`, {
          method: "GET",
          headers: {
            "Accept": "application/json"
          }
        });
        if (!response.ok) {
          throw new Error(`Patterns failed: ${response.status}`);
        }
        const result = yield response.json();
        return result.patterns || {};
      } catch (error) {
        console.error("Patterns error:", error);
        return {};
      }
    });
  }
  /**
   * Build CQL query from search term and filters
   */
  buildSimpleQuery(searchTerm, filters) {
    const queryParts = [];
    if (searchTerm.trim()) {
      queryParts.push(`title any "${searchTerm}" OR description any "${searchTerm}"`);
    }
    if (filters) {
      if (filters.tipoDocumento && filters.tipoDocumento.length > 0) {
        const typeQueries = filters.tipoDocumento.map((type) => `tipoDocumento exact "${type}"`);
        queryParts.push(`(${typeQueries.join(" OR ")})`);
      }
      if (filters.autoridade && filters.autoridade.length > 0) {
        const authQueries = filters.autoridade.map((auth) => `autoridade exact "${auth}"`);
        queryParts.push(`(${authQueries.join(" OR ")})`);
      }
      if (filters.localidade && filters.localidade.length > 0) {
        const locQueries = filters.localidade.map((loc) => `localidade any "${loc}"`);
        queryParts.push(`(${locQueries.join(" OR ")})`);
      }
    }
    return queryParts.length > 0 ? queryParts.join(" AND ") : "*";
  }
  /**
   * Quick search utility for transport legislation
   */
  searchTransportLegislation(term = "") {
    return __async$5(this, null, function* () {
      const transportQuery = term ? `(title any "${term}" OR description any "${term}") AND (title any "transporte" OR description any "transporte" OR subject any "transporte")` : 'title any "transporte" OR description any "transporte" OR subject any "transporte"';
      return this.searchDocuments({
        cql_query: transportQuery,
        start_record: 1,
        max_records: 50,
        include_content: false,
        filters: {
          tipoDocumento: [],
          autoridade: [],
          localidade: [],
          subject: []
        }
      });
    });
  }
  /**
   * Find cross-references within document content with caching
   */
  findCrossReferences(documentUrn) {
    return __async$5(this, null, function* () {
      const cacheKey = cacheService.createCrossReferencesKey(documentUrn);
      const cachedRefs = cacheService.get(cacheKey);
      if (cachedRefs) {
        return cachedRefs;
      }
      try {
        const response = yield fetch(
          `${this.baseURL}/api/lexml/document/${encodeURIComponent(documentUrn)}/references`,
          {
            method: "GET",
            headers: {
              "Accept": "application/json"
            }
          }
        );
        if (!response.ok) {
          throw new Error(`Cross-reference discovery failed: ${response.status}`);
        }
        const references = yield response.json();
        cacheService.set(cacheKey, references);
        return references;
      } catch (error) {
        console.error("Cross-reference discovery error:", error);
        const fallbackRefs = yield this.extractLocalCrossReferences(documentUrn);
        cacheService.set(cacheKey, fallbackRefs, 10 * 60 * 1e3);
        return fallbackRefs;
      }
    });
  }
  /**
   * Extract cross-references using local pattern matching
   */
  extractLocalCrossReferences(documentUrn) {
    return __async$5(this, null, function* () {
      const content = yield this.getDocumentContent(documentUrn);
      if (!content || !content.full_text) {
        return { references: [], related_documents: [] };
      }
      const text = content.full_text;
      const references = [];
      const patterns = [
        // Lei patterns
        {
          regex: /Lei\s+(?:nº\s*|n\.?\s*)?(\d+(?:[.,]\d+)?)\s*,?\s*de\s+(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})/gi,
          type: "law",
          extract: (match) => ({
            text: match[0],
            description: `Lei ${match[1]} de ${match[2]} de ${match[3]} de ${match[4]}`
          })
        },
        // Decreto patterns
        {
          regex: /Decreto\s+(?:nº\s*|n\.?\s*)?(\d+(?:[.,]\d+)?)\s*,?\s*de\s+(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})/gi,
          type: "decree",
          extract: (match) => ({
            text: match[0],
            description: `Decreto ${match[1]} de ${match[2]} de ${match[3]} de ${match[4]}`
          })
        },
        // Article patterns
        {
          regex: /art\.?\s*(\d+(?:-[A-Z])?)/gi,
          type: "article",
          extract: (match) => ({
            text: match[0],
            description: `Artigo ${match[1]}`
          })
        },
        // Paragraph patterns
        {
          regex: /§\s*(\d+)º?/gi,
          type: "paragraph",
          extract: (match) => ({
            text: match[0],
            description: `Parágrafo ${match[1]}`
          })
        },
        // Inciso patterns
        {
          regex: /inciso\s+([IVX]+)/gi,
          type: "paragraph",
          extract: (match) => ({
            text: match[0],
            description: `Inciso ${match[1]}`
          })
        }
      ];
      for (const pattern of patterns) {
        let match;
        while ((match = pattern.regex.exec(text)) !== null) {
          const extracted = pattern.extract(match);
          references.push(__spreadValues$1({
            type: pattern.type
          }, extracted));
        }
      }
      const uniqueReferences = references.filter(
        (ref, index, self) => index === self.findIndex((r) => r.text === ref.text)
      );
      return {
        references: uniqueReferences.slice(0, 20),
        // Limit to 20 references
        related_documents: []
        // Would need API for related documents
      };
    });
  }
  /**
   * Get related documents based on content similarity and citations with caching
   */
  getRelatedDocuments(documentUrn, maxResults = 10) {
    return __async$5(this, null, function* () {
      const cacheKey = cacheService.createRelatedDocumentsKey(documentUrn, maxResults);
      const cachedRelated = cacheService.get(cacheKey);
      if (cachedRelated) {
        return __spreadProps(__spreadValues$1({}, cachedRelated), {
          cache_hit: true
        });
      }
      try {
        const response = yield fetch(
          `${this.baseURL}/api/lexml/document/${encodeURIComponent(documentUrn)}/related?max_results=${maxResults}`,
          {
            method: "GET",
            headers: {
              "Accept": "application/json"
            }
          }
        );
        if (!response.ok) {
          throw new Error(`Related documents failed: ${response.status}`);
        }
        const relatedDocs = yield response.json();
        cacheService.set(cacheKey, relatedDocs);
        return relatedDocs;
      } catch (error) {
        console.error("Related documents error:", error);
        const fallbackRelated = yield this.findSimilarDocumentsBySubject(documentUrn, maxResults);
        cacheService.set(cacheKey, fallbackRelated, 10 * 60 * 1e3);
        return fallbackRelated;
      }
    });
  }
  /**
   * Find similar documents by subject and document type
   */
  findSimilarDocumentsBySubject(documentUrn, maxResults) {
    return __async$5(this, null, function* () {
      const content = yield this.getDocumentContent(documentUrn);
      if (!content || !content.metadata) {
        return {
          documents: [],
          total_found: 0,
          start_record: 1,
          records_returned: 0,
          search_time_ms: 0,
          data_source: "csv-fallback",
          cache_hit: false,
          api_status: "no-content"
        };
      }
      const subjects = content.metadata.subject || [];
      if (subjects.length === 0) {
        return {
          documents: [],
          total_found: 0,
          start_record: 1,
          records_returned: 0,
          search_time_ms: 0,
          data_source: "csv-fallback",
          cache_hit: false,
          api_status: "no-subjects"
        };
      }
      const subjectQueries = subjects.slice(0, 3).map(
        (subject) => `subject any "${subject}"`
      );
      const cqlQuery = `(${subjectQueries.join(" OR ")}) AND NOT urn exact "${documentUrn}"`;
      return this.searchDocuments({
        cql_query: cqlQuery,
        start_record: 1,
        max_records: maxResults,
        include_content: false,
        filters: {
          tipoDocumento: [],
          autoridade: [],
          localidade: [],
          subject: []
        }
      });
    });
  }
}
const lexmlAPI = new LexMLAPIService();
var __defProp = Object.defineProperty;
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
const defaultFilters = {
  tipoDocumento: [],
  autoridade: [],
  localidade: [],
  subject: []
};
function useLexMLSearch(options = {}) {
  const {
    debounceMs = 500,
    autoSearch = false,
    minQueryLength = 3,
    defaultMaxRecords = 50
  } = options;
  const [searchState, setSearchState] = reactExports.useState({
    query: "",
    results: [],
    isLoading: false,
    resultCount: 0,
    totalAvailable: 0,
    searchTime: 0,
    dataSource: "live-api",
    apiStatus: "connected",
    filters: defaultFilters,
    currentPage: 1,
    hasNextPage: false
  });
  const [apiHealth, setApiHealth] = reactExports.useState(null);
  const debounceTimeoutRef = reactExports.useRef(null);
  const abortControllerRef = reactExports.useRef(null);
  const updateSearchState = reactExports.useCallback((updates) => {
    setSearchState((prev) => __spreadValues(__spreadValues({}, prev), updates));
  }, []);
  const performSearch = reactExports.useCallback((_0, ..._1) => __async$4(null, [_0, ..._1], function* (query, filters = {}, loadMore = false) {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (!query.trim() && Object.keys(filters).length === 0) {
      updateSearchState({
        results: [],
        resultCount: 0,
        totalAvailable: 0,
        isLoading: false
      });
      return;
    }
    if (query.trim() && query.trim().length < minQueryLength) {
      return;
    }
    updateSearchState({
      isLoading: true,
      query: query.trim()
    });
    try {
      const startRecord = loadMore ? searchState.results.length + 1 : 1;
      const searchRequest = {
        query: query.trim() || void 0,
        filters: __spreadValues(__spreadValues(__spreadValues({}, defaultFilters), searchState.filters), filters),
        start_record: startRecord,
        max_records: defaultMaxRecords,
        include_content: false
      };
      const response = yield lexmlAPI.searchDocuments(searchRequest);
      const newResults = loadMore ? [...searchState.results, ...response.documents] : response.documents;
      updateSearchState({
        results: newResults,
        resultCount: response.total_found || response.documents.length,
        totalAvailable: response.total_found === void 0 ? "unlimited" : response.total_found,
        searchTime: response.search_time_ms,
        dataSource: response.data_source,
        apiStatus: response.api_status === "error" ? "error" : response.data_source === "csv-fallback" ? "fallback" : "connected",
        isLoading: false,
        currentPage: Math.ceil(newResults.length / defaultMaxRecords),
        hasNextPage: response.next_start_record !== void 0 && response.next_start_record !== null,
        filters: __spreadValues(__spreadValues(__spreadValues({}, defaultFilters), searchState.filters), filters)
      });
    } catch (error) {
      console.error("Search error:", error);
      updateSearchState({
        isLoading: false,
        apiStatus: "error",
        results: loadMore ? searchState.results : [],
        resultCount: loadMore ? searchState.resultCount : 0
      });
    }
  }), [searchState.results, searchState.filters, minQueryLength, defaultMaxRecords, updateSearchState]);
  const debouncedSearch = reactExports.useCallback((query, filters) => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    debounceTimeoutRef.current = setTimeout(() => {
      performSearch(query, filters);
    }, debounceMs);
  }, [performSearch, debounceMs]);
  const searchDocuments = reactExports.useCallback((query, filters) => __async$4(null, null, function* () {
    if (autoSearch) {
      debouncedSearch(query, filters);
    } else {
      yield performSearch(query, filters);
    }
  }), [autoSearch, debouncedSearch, performSearch]);
  const searchWithCQL = reactExports.useCallback((cqlQuery) => __async$4(null, null, function* () {
    updateSearchState({ isLoading: true });
    try {
      const searchRequest = {
        cql_query: cqlQuery,
        start_record: 1,
        max_records: defaultMaxRecords,
        include_content: false,
        filters: defaultFilters
      };
      const response = yield lexmlAPI.searchDocuments(searchRequest);
      updateSearchState({
        results: response.documents,
        resultCount: response.total_found || response.documents.length,
        totalAvailable: response.total_found === void 0 ? "unlimited" : response.total_found,
        searchTime: response.search_time_ms,
        dataSource: response.data_source,
        apiStatus: response.api_status === "error" ? "error" : response.data_source === "csv-fallback" ? "fallback" : "connected",
        isLoading: false,
        currentPage: 1,
        hasNextPage: response.next_start_record !== void 0,
        query: `CQL: ${cqlQuery}`
      });
    } catch (error) {
      console.error("CQL search error:", error);
      updateSearchState({
        isLoading: false,
        apiStatus: "error"
      });
    }
  }), [defaultMaxRecords, updateSearchState]);
  const loadMoreResults = reactExports.useCallback(() => __async$4(null, null, function* () {
    if (!searchState.hasNextPage || searchState.isLoading) {
      return;
    }
    yield performSearch(searchState.query, searchState.filters, true);
  }), [searchState.hasNextPage, searchState.isLoading, searchState.query, searchState.filters, performSearch]);
  const clearResults = reactExports.useCallback(() => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    updateSearchState({
      query: "",
      results: [],
      resultCount: 0,
      totalAvailable: 0,
      searchTime: 0,
      isLoading: false,
      currentPage: 1,
      hasNextPage: false,
      filters: defaultFilters
    });
  }, [updateSearchState]);
  const setFilters = reactExports.useCallback((filters) => {
    const newFilters = __spreadValues(__spreadValues({}, searchState.filters), filters);
    updateSearchState({ filters: newFilters });
    if (searchState.query.trim()) {
      if (autoSearch) {
        debouncedSearch(searchState.query, newFilters);
      }
    }
  }, [searchState.filters, searchState.query, autoSearch, debouncedSearch, updateSearchState]);
  const refreshHealth = reactExports.useCallback(() => __async$4(null, null, function* () {
    try {
      const health = yield lexmlAPI.getHealthStatus();
      setApiHealth(health);
    } catch (error) {
      console.error("Health check error:", error);
      setApiHealth(null);
    }
  }), []);
  reactExports.useEffect(() => {
    refreshHealth();
    const healthInterval = setInterval(refreshHealth, 5 * 60 * 1e3);
    return () => {
      clearInterval(healthInterval);
    };
  }, [refreshHealth]);
  reactExports.useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);
  return {
    searchState,
    searchDocuments,
    searchWithCQL,
    loadMoreResults,
    clearResults,
    setFilters,
    apiHealth,
    refreshHealth
  };
}
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
const LexMLSearchBar = ({
  onSearch,
  onCQLSearch,
  placeholder = "Search Brazilian legislation...",
  initialValue = "",
  isLoading = false,
  showAdvanced = true,
  className = ""
}) => {
  const [query, setQuery] = reactExports.useState(initialValue);
  const [suggestions, setSuggestions] = reactExports.useState([]);
  const [showSuggestions, setShowSuggestions] = reactExports.useState(false);
  const [isCQLMode, setIsCQLMode] = reactExports.useState(false);
  const [cqlValid, setCQLValid] = reactExports.useState(null);
  const inputRef = reactExports.useRef(null);
  const suggestionsRef = reactExports.useRef(null);
  const debounceRef = reactExports.useRef(null);
  const handleInputChange = (value) => {
    setQuery(value);
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }
    if (value.length >= 2) {
      debounceRef.current = setTimeout(() => __async$3(null, null, function* () {
        try {
          const newSuggestions = yield lexmlAPI.getSuggestions(value);
          setSuggestions(newSuggestions);
          setShowSuggestions(true);
        } catch (error) {
          console.error("Suggestions error:", error);
          setSuggestions([]);
        }
      }), 300);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
    if (isCQLMode && value.trim()) {
      validateCQL(value);
    }
  };
  const validateCQL = (cqlQuery) => __async$3(null, null, function* () {
    try {
      const result = yield lexmlAPI.parseCQLQuery(cqlQuery);
      setCQLValid(result.isValid);
    } catch (error) {
      setCQLValid(false);
    }
  });
  const handleSearch = () => {
    const trimmedQuery = query.trim();
    if (!trimmedQuery) return;
    if (isCQLMode && onCQLSearch) {
      onCQLSearch(trimmedQuery);
    } else {
      onSearch(trimmedQuery);
    }
    setShowSuggestions(false);
  };
  const handleSuggestionSelect = (suggestion) => {
    var _a;
    if (suggestion.cql_query) {
      setQuery(suggestion.cql_query);
      setIsCQLMode(true);
      if (onCQLSearch) {
        onCQLSearch(suggestion.cql_query);
      }
    } else {
      setQuery(suggestion.text);
      onSearch(suggestion.text);
    }
    setShowSuggestions(false);
    (_a = inputRef.current) == null ? void 0 : _a.focus();
  };
  const handleKeyDown = (e) => {
    var _a;
    if (e.key === "Enter") {
      e.preventDefault();
      handleSearch();
    } else if (e.key === "Escape") {
      setShowSuggestions(false);
      (_a = inputRef.current) == null ? void 0 : _a.blur();
    }
  };
  reactExports.useEffect(() => {
    const handleClickOutside = (event) => {
      var _a;
      if (suggestionsRef.current && !suggestionsRef.current.contains(event.target) && !((_a = inputRef.current) == null ? void 0 : _a.contains(event.target))) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  reactExports.useEffect(() => {
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);
  const getSuggestionIcon = (type) => {
    const icons = {
      "tipoDocumento": "📋",
      "autoridade": "🏛️",
      "localidade": "📍",
      "subject": "🏷️",
      "urn": "🔗",
      "cql": "⚡",
      "history": "🕒",
      "skos": "📚"
    };
    return icons[type] || "🔍";
  };
  const getSuggestionColor = (type) => {
    const colors = {
      "tipoDocumento": "bg-blue-50 text-blue-700",
      "autoridade": "bg-purple-50 text-purple-700",
      "localidade": "bg-green-50 text-green-700",
      "subject": "bg-yellow-50 text-yellow-700",
      "urn": "bg-gray-50 text-gray-700",
      "cql": "bg-red-50 text-red-700",
      "history": "bg-indigo-50 text-indigo-700",
      "skos": "bg-pink-50 text-pink-700"
    };
    return colors[type] || "bg-gray-50 text-gray-700";
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `relative w-full ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none", children: /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "h-5 w-5 text-gray-400", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" }) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          ref: inputRef,
          id: "lexml-search-input",
          name: "lexml-search",
          type: "text",
          value: query,
          onChange: (e) => handleInputChange(e.target.value),
          onKeyDown: handleKeyDown,
          onFocus: () => suggestions.length > 0 && setShowSuggestions(true),
          placeholder: isCQLMode ? 'Enter CQL query (e.g., tipoDocumento exact "Lei")' : placeholder,
          className: `
            w-full pl-10 pr-20 py-3 border rounded-lg
            focus:ring-2 focus:ring-blue-500 focus:border-blue-500
            ${isCQLMode ? "bg-red-50 border-red-200" : "bg-white border-gray-300"}
            ${isCQLMode && cqlValid === false ? "border-red-500" : ""}
            ${isCQLMode && cqlValid === true ? "border-green-500" : ""}
            transition-colors duration-200
          `,
          disabled: isLoading,
          autoComplete: "search",
          "aria-label": isCQLMode ? "CQL search query" : "Search Brazilian legislation"
        }
      ),
      showAdvanced && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => {
            setIsCQLMode(!isCQLMode);
            setCQLValid(null);
            if (!isCQLMode) {
              setQuery("");
            }
          },
          className: `
              absolute inset-y-0 right-12 px-2 flex items-center
              text-xs font-medium rounded-r-none
              ${isCQLMode ? "text-red-600 bg-red-100 hover:bg-red-200" : "text-gray-500 hover:text-gray-700"}
              transition-colors duration-200
            `,
          title: isCQLMode ? "Switch to simple search" : "Switch to CQL mode",
          children: isCQLMode ? "CQL" : "ABC"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: handleSearch,
          disabled: isLoading || !query.trim(),
          className: "\n            absolute inset-y-0 right-0 px-4 flex items-center\n            bg-blue-600 text-white rounded-r-lg\n            hover:bg-blue-700 focus:ring-2 focus:ring-blue-500\n            disabled:bg-gray-400 disabled:cursor-not-allowed\n            transition-colors duration-200\n          ",
          children: isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "h-4 w-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" }) })
        }
      )
    ] }),
    isCQLMode && query.trim() && cqlValid !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `mt-1 text-xs ${cqlValid ? "text-green-600" : "text-red-600"}`, children: cqlValid ? "✓ Valid CQL query" : "✗ Invalid CQL syntax" }),
    showSuggestions && suggestions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        ref: suggestionsRef,
        className: "absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg max-h-96 overflow-y-auto",
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-gray-500 mb-2", children: "Search suggestions from LexML Brasil:" }),
          suggestions.map((suggestion, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              onClick: () => handleSuggestionSelect(suggestion),
              className: "\n                  w-full text-left px-3 py-2 rounded-md\n                  hover:bg-gray-50 focus:bg-gray-50\n                  flex items-center gap-3\n                  transition-colors duration-150\n                ",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg", children: getSuggestionIcon(suggestion.type) }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 min-w-0", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-gray-900 truncate", children: suggestion.text }),
                  suggestion.metadata.document_count && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-gray-500", children: [
                    suggestion.metadata.document_count.toLocaleString(),
                    " documents"
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                  px-2 py-1 text-xs rounded-full
                  ${getSuggestionColor(suggestion.type)}
                `, children: suggestion.type })
              ]
            },
            index
          ))
        ] })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 text-xs text-gray-500", children: isCQLMode ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
      "CQL mode: Use academic queries like ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: 'tipoDocumento exact "Lei" AND autoridade exact "federal"' })
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Search across titles, descriptions, and subjects. Use quotes for exact phrases." }) })
  ] });
};
var LexMLSearchBar_default = LexMLSearchBar;
const documentTypes = [
  { value: "Lei", label: "Lei", description: "Federal, state, or municipal laws" },
  { value: "Decreto", label: "Decreto", description: "Executive decrees and regulations" },
  { value: "Decreto-Lei", label: "Decreto-Lei", description: "Decree-laws (historical)" },
  { value: "Medida Provisória", label: "Medida Provisória", description: "Provisional measures" },
  { value: "Portaria", label: "Portaria", description: "Administrative ordinances" },
  { value: "Resolução", label: "Resolução", description: "Resolutions and decisions" },
  { value: "Instrução Normativa", label: "Instrução Normativa", description: "Normative instructions" },
  { value: "Emenda Constitucional", label: "Emenda Constitucional", description: "Constitutional amendments" },
  { value: "Acórdão", label: "Acórdão", description: "Court decisions and rulings" },
  { value: "Parecer", label: "Parecer", description: "Legal opinions and reports" }
];
const autoridades = [
  { value: "federal", label: "Federal", description: "Federal government authorities" },
  { value: "estadual", label: "Estadual", description: "State government authorities" },
  { value: "municipal", label: "Municipal", description: "Municipal government authorities" },
  { value: "distrital", label: "Distrital", description: "Federal District authorities" }
];
const brazilianStates = [
  { code: "br", name: "Federal (Brasil)", description: "Federal legislation" },
  { code: "sao.paulo", name: "São Paulo", description: "SP state legislation" },
  { code: "rio.de.janeiro", name: "Rio de Janeiro", description: "RJ state legislation" },
  { code: "minas.gerais", name: "Minas Gerais", description: "MG state legislation" },
  { code: "rio.grande.sul", name: "Rio Grande do Sul", description: "RS state legislation" },
  { code: "parana", name: "Paraná", description: "PR state legislation" },
  { code: "bahia", name: "Bahia", description: "BA state legislation" },
  { code: "distrito.federal", name: "Distrito Federal", description: "DF legislation" },
  { code: "espirito.santo", name: "Espírito Santo", description: "ES state legislation" },
  { code: "goias", name: "Goiás", description: "GO state legislation" },
  { code: "santa.catarina", name: "Santa Catarina", description: "SC state legislation" },
  { code: "ceara", name: "Ceará", description: "CE state legislation" }
];
const transportSubjects = [
  "transporte",
  "transporte urbano",
  "transporte público",
  "transporte de carga",
  "transporte rodoviário",
  "transporte ferroviário",
  "transporte aquaviário",
  "transporte aéreo",
  "logística",
  "infraestrutura",
  "mobilidade urbana",
  "trânsito",
  "pedágio",
  "combustível",
  "frete",
  "carga",
  "veículo"
];
const LexMLFilters = ({
  filters,
  onFiltersChange,
  isCollapsed = false,
  onToggleCollapse,
  className = ""
}) => {
  const [dateFrom, setDateFrom] = reactExports.useState(filters.date_from || "");
  const [dateTo, setDateTo] = reactExports.useState(filters.date_to || "");
  const handleDocumentTypeChange = (type, checked) => {
    const newTypes = checked ? [...filters.tipoDocumento, type] : filters.tipoDocumento.filter((t) => t !== type);
    onFiltersChange({ tipoDocumento: newTypes });
  };
  const handleAutoridadeChange = (auth, checked) => {
    const newAuth = checked ? [...filters.autoridade, auth] : filters.autoridade.filter((a) => a !== auth);
    onFiltersChange({ autoridade: newAuth });
  };
  const handleLocalidadeChange = (loc, checked) => {
    const newLoc = checked ? [...filters.localidade, loc] : filters.localidade.filter((l) => l !== loc);
    onFiltersChange({ localidade: newLoc });
  };
  const handleSubjectChange = (subject, checked) => {
    const newSubjects = checked ? [...filters.subject, subject] : filters.subject.filter((s) => s !== subject);
    onFiltersChange({ subject: newSubjects });
  };
  const handleDateFromChange = (date) => {
    setDateFrom(date);
    onFiltersChange({ date_from: date || void 0 });
  };
  const handleDateToChange = (date) => {
    setDateTo(date);
    onFiltersChange({ date_to: date || void 0 });
  };
  const clearAllFilters = () => {
    setDateFrom("");
    setDateTo("");
    onFiltersChange({
      tipoDocumento: [],
      autoridade: [],
      localidade: [],
      subject: [],
      date_from: void 0,
      date_to: void 0
    });
  };
  const activeFilterCount = filters.tipoDocumento.length + filters.autoridade.length + filters.localidade.length + filters.subject.length + (filters.date_from ? 1 : 0) + (filters.date_to ? 1 : 0);
  if (isCollapsed) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `bg-white border border-gray-200 rounded-lg p-4 ${className}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-gray-700", children: "Filters" }),
        activeFilterCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full", children: [
          activeFilterCount,
          " active"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: onToggleCollapse,
          className: "text-sm text-blue-600 hover:text-blue-800",
          children: "Show filters"
        }
      )
    ] }) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `bg-white border border-gray-200 rounded-lg ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between p-4 border-b border-gray-200", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-semibold text-gray-800", children: "Advanced Filters" }),
        activeFilterCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-blue-100 text-blue-800 text-sm px-2 py-1 rounded-full", children: [
          activeFilterCount,
          " active"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        activeFilterCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: clearAllFilters,
            className: "text-sm text-red-600 hover:text-red-800",
            children: "Clear all"
          }
        ),
        onToggleCollapse && /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: onToggleCollapse,
            className: "text-sm text-gray-600 hover:text-gray-800",
            children: "Hide filters"
          }
        )
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-4 space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Document Type" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-2", children: documentTypes.map((type) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center space-x-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.tipoDocumento.includes(type.value),
              onChange: (e) => handleDocumentTypeChange(type.value, e.target.checked),
              className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-700", children: type.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-gray-400 text-xs", children: [
            "(",
            type.description,
            ")"
          ] })
        ] }, type.value)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Authority Level" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-2", children: autoridades.map((auth) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center space-x-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.autoridade.includes(auth.value),
              onChange: (e) => handleAutoridadeChange(auth.value, e.target.checked),
              className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-700", children: auth.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-gray-400 text-xs", children: [
            "(",
            auth.description,
            ")"
          ] })
        ] }, auth.value)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Geographic Scope" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto", children: brazilianStates.map((state) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center space-x-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.localidade.includes(state.code),
              onChange: (e) => handleLocalidadeChange(state.code, e.target.checked),
              className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-700", children: state.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-gray-400 text-xs", children: [
            "(",
            state.description,
            ")"
          ] })
        ] }, state.code)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Date Range" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-xs text-gray-600 mb-1", children: "From" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: dateFrom,
                onChange: (e) => handleDateFromChange(e.target.value),
                className: "w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-xs text-gray-600 mb-1", children: "To" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: dateTo,
                onChange: (e) => handleDateToChange(e.target.value),
                className: "w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              }
            )
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Transport Topics" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 md:grid-cols-3 gap-2 max-h-32 overflow-y-auto", children: transportSubjects.map((subject) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center space-x-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.subject.includes(subject),
              onChange: (e) => handleSubjectChange(subject, e.target.checked),
              className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-700 capitalize", children: subject })
        ] }, subject)) })
      ] }),
      activeFilterCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 p-3 bg-blue-50 rounded-lg", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-medium text-blue-800 mb-2", children: "Active Filters:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          filters.tipoDocumento.map((type) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full", children: [
            "Type: ",
            type
          ] }, type)),
          filters.autoridade.map((auth) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full", children: [
            "Authority: ",
            auth
          ] }, auth)),
          filters.localidade.map((loc) => {
            var _a;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full", children: [
              "Location: ",
              ((_a = brazilianStates.find((s) => s.code === loc)) == null ? void 0 : _a.name) || loc
            ] }, loc);
          }),
          filters.subject.map((subj) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded-full", children: [
            "Topic: ",
            subj
          ] }, subj)),
          filters.date_from && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full", children: [
            "From: ",
            filters.date_from
          ] }),
          filters.date_to && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full", children: [
            "To: ",
            filters.date_to
          ] })
        ] })
      ] })
    ] })
  ] });
};
var LexMLFilters_default = LexMLFilters;
const sourceConfigs = {
  "live-api": {
    icon: "🔴",
    label: "Live API",
    description: "Real-time data from LexML Brasil",
    color: "text-green-700",
    bgColor: "bg-green-50",
    borderColor: "border-green-200"
  },
  "cached-api": {
    icon: "🟡",
    label: "Cached",
    description: "Recent data from cache",
    color: "text-blue-700",
    bgColor: "bg-blue-50",
    borderColor: "border-blue-200"
  },
  "csv-fallback": {
    icon: "⚫",
    label: "Fallback",
    description: "Local dataset (890 documents)",
    color: "text-gray-700",
    bgColor: "bg-gray-50",
    borderColor: "border-gray-200"
  }
};
const apiStatusConfigs = {
  connected: {
    icon: "✅",
    text: "API Connected",
    color: "text-green-600"
  },
  fallback: {
    icon: "⚠️",
    text: "Using Fallback",
    color: "text-yellow-600"
  },
  error: {
    icon: "❌",
    text: "API Error",
    color: "text-red-600"
  }
};
const DataSourceIndicator = ({
  dataSource,
  apiStatus,
  searchTime,
  resultCount,
  totalAvailable,
  className = ""
}) => {
  const sourceConfig = sourceConfigs[dataSource];
  const statusConfig = apiStatusConfigs[apiStatus];
  const formatSearchTime = (timeMs) => {
    if (!timeMs) return "";
    if (timeMs < 1e3) return `${Math.round(timeMs)}ms`;
    return `${(timeMs / 1e3).toFixed(1)}s`;
  };
  const formatResultCount = () => {
    if (resultCount === void 0) return "";
    if (totalAvailable === "unlimited") {
      return `${resultCount.toLocaleString()} results (unlimited database)`;
    } else if (totalAvailable && totalAvailable > resultCount) {
      return `${resultCount.toLocaleString()} of ${totalAvailable.toLocaleString()} results`;
    } else {
      return `${resultCount.toLocaleString()} results`;
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex items-center gap-4 p-3 rounded-lg border ${sourceConfig.bgColor} ${sourceConfig.borderColor} ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg", title: sourceConfig.description, children: sourceConfig.icon }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `text-sm font-medium ${sourceConfig.color}`, children: sourceConfig.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-gray-500", children: sourceConfig.description })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-2 py-1 rounded-md bg-white/50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: statusConfig.icon }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `text-sm font-medium ${statusConfig.color}`, children: statusConfig.text })
    ] }),
    searchTime !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-2 py-1 rounded-md bg-white/50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: "⚡" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: formatSearchTime(searchTime) })
    ] }),
    resultCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-2 py-1 rounded-md bg-white/50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: "📄" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: formatResultCount() })
    ] }),
    dataSource === "csv-fallback" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-3 py-1 rounded-md bg-yellow-100 border border-yellow-300", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: "ℹ️" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-yellow-800", children: "Limited to transport legislation dataset" })
    ] }),
    dataSource === "live-api" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-3 py-1 rounded-md bg-green-100 border border-green-300", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: "🚀" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-green-800", children: "Complete Brazilian legal database" })
    ] })
  ] });
};
var DataSourceIndicator_default = DataSourceIndicator;
const DocumentCard = ({ document: document2, onClick }) => {
  const formatDate = (dateString) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString("pt-BR", {
        year: "numeric",
        month: "long",
        day: "numeric"
      });
    } catch (e) {
      return dateString;
    }
  };
  const getDocumentTypeColor = (type) => {
    const colors = {
      "Lei": "bg-blue-100 text-blue-800",
      "Decreto": "bg-green-100 text-green-800",
      "Portaria": "bg-yellow-100 text-yellow-800",
      "Resolução": "bg-purple-100 text-purple-800",
      "Medida Provisória": "bg-red-100 text-red-800",
      "Instrução Normativa": "bg-indigo-100 text-indigo-800"
    };
    return colors[type] || "bg-gray-100 text-gray-800";
  };
  const getAuthorityIcon = (authority) => {
    const icons = {
      "federal": "🇧🇷",
      "estadual": "🏛️",
      "municipal": "🏢",
      "distrital": "🏛️"
    };
    return icons[authority] || "📋";
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow duration-200 cursor-pointer",
      onClick: () => onClick == null ? void 0 : onClick(document2),
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between mb-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 flex-wrap", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `px-2 py-1 text-xs font-medium rounded-full ${getDocumentTypeColor(document2.metadata.tipoDocumento)}`, children: document2.metadata.tipoDocumento }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-1 text-xs text-gray-600", children: [
              getAuthorityIcon(document2.metadata.autoridade),
              document2.metadata.autoridade
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-gray-500", children: [
              "📍 ",
              document2.metadata.localidade
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
            px-2 py-1 text-xs rounded-full
            ${document2.data_source === "live-api" ? "bg-green-100 text-green-700" : document2.data_source === "cached-api" ? "bg-blue-100 text-blue-700" : "bg-gray-100 text-gray-700"}
          `, children: document2.data_source === "live-api" ? "🔴 Live" : document2.data_source === "cached-api" ? "🟡 Cached" : "⚫ Fallback" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-semibold text-gray-900 mb-2 line-clamp-2", children: document2.metadata.title }),
        document2.metadata.description && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-600 mb-3 line-clamp-2", children: document2.metadata.description }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4 text-sm text-gray-500", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-1", children: [
              "📅 ",
              formatDate(document2.metadata.date)
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-1", children: [
              "🔗 ",
              document2.metadata.urn.split(":").pop() || "N/A"
            ] })
          ] }),
          document2.metadata.subject.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1", children: [
            document2.metadata.subject.slice(0, 5).map((subject, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: "bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded-full",
                children: subject
              },
              index
            )),
            document2.metadata.subject.length > 5 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded-full", children: [
              "+",
              document2.metadata.subject.length - 5,
              " more"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 pt-3 border-t border-gray-100 flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center gap-1", children: [
            "📄 View Full Document",
            /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-4 h-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" }) })
          ] }),
          document2.metadata.identifier && /* @__PURE__ */ jsxRuntimeExports.jsx(
            "a",
            {
              href: document2.metadata.identifier,
              target: "_blank",
              rel: "noopener noreferrer",
              onClick: (e) => e.stopPropagation(),
              className: "text-gray-600 hover:text-gray-800 text-sm flex items-center gap-1",
              children: "🌐 Official Source"
            }
          )
        ] })
      ]
    }
  );
};
const SearchResults = ({
  documents,
  dataSource,
  apiStatus,
  searchTime,
  resultCount,
  totalAvailable,
  isLoading = false,
  hasNextPage = false,
  onLoadMore,
  onDocumentClick,
  className = ""
}) => {
  const [viewMode, setViewMode] = reactExports.useState("card");
  if (!isLoading && documents.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `bg-white border border-gray-200 rounded-lg p-8 text-center ${className}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-400 mb-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-16 h-16 mx-auto", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 1, d: "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" }) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900 mb-2", children: "No documents found" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-500 mb-4", children: "Try adjusting your search terms or filters to find relevant legislation." }),
      apiStatus === "fallback" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-yellow-50 border border-yellow-200 rounded-lg p-4 max-w-md mx-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-yellow-800", children: "⚠️ Currently using fallback dataset. Try searching for transport-related terms or wait for API connectivity to restore for full database access." }) })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      DataSourceIndicator_default,
      {
        dataSource,
        apiStatus,
        searchTime,
        resultCount,
        totalAvailable,
        className: "mb-4"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between mb-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-xl font-semibold text-gray-900", children: "Search Results" }),
        resultCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-600 mt-1", children: dataSource === "csv-fallback" ? `Showing ${documents.length} of ${resultCount} results from transport legislation dataset` : totalAvailable === "unlimited" ? `Showing ${documents.length} results from complete legal database` : `Showing ${documents.length} of ${totalAvailable == null ? void 0 : totalAvailable.toLocaleString()} results` })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "View:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex rounded-lg border border-gray-300", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => setViewMode("card"),
              className: `px-3 py-1 text-sm rounded-l-lg ${viewMode === "card" ? "bg-blue-500 text-white" : "bg-white text-gray-700 hover:bg-gray-50"}`,
              children: "Cards"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => setViewMode("list"),
              className: `px-3 py-1 text-sm rounded-r-lg ${viewMode === "list" ? "bg-blue-500 text-white" : "bg-white text-gray-700 hover:bg-gray-50"}`,
              children: "List"
            }
          )
        ] })
      ] })
    ] }),
    isLoading && documents.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center py-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-600", children: apiStatus === "connected" ? "Searching LexML Brasil database..." : "Searching documents..." })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: viewMode === "card" ? "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" : "space-y-4", children: documents.map((document2, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      DocumentCard,
      {
        document: document2,
        onClick: onDocumentClick
      },
      `${document2.metadata.urn}-${index}`
    )) }),
    hasNextPage && onLoadMore && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-8 text-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        onClick: onLoadMore,
        disabled: isLoading,
        className: "\n              px-6 py-3 bg-blue-600 text-white rounded-lg\n              hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2\n              disabled:bg-gray-400 disabled:cursor-not-allowed\n              flex items-center gap-2 mx-auto\n              transition-colors duration-200\n            ",
        children: isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" }),
          "Loading more..."
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          "📄 Load More Results",
          /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-4 h-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M19 9l-7 7-7-7" }) })
        ] })
      }
    ) }),
    dataSource === "csv-fallback" && documents.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-blue-500 text-xl", children: "🚀" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-medium text-blue-900 mb-1", children: "Want access to the complete Brazilian legal database?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-blue-800 mb-3", children: "You're currently viewing results from our transport legislation dataset (890 documents). The live API provides access to millions of documents across all legal areas." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "text-sm text-blue-600 hover:text-blue-800 font-medium", children: "Check API Status →" })
      ] })
    ] }) })
  ] });
};
var SearchResults_default = SearchResults;
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
const citationFormats = [
  {
    id: "abnt",
    name: "ABNT",
    format: (doc) => {
      const date = new Date(doc.metadata.date);
      date.getFullYear();
      const formattedDate = date.toLocaleDateString("pt-BR");
      if (doc.metadata.tipoDocumento === "Lei") {
        return `${doc.metadata.localidade.toUpperCase()}. Lei nº [número], de ${formattedDate}. ${doc.metadata.title}. Disponível em: ${doc.metadata.identifier}. Acesso em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}.`;
      }
      return `${doc.metadata.localidade.toUpperCase()}. ${doc.metadata.tipoDocumento} [número], de ${formattedDate}. ${doc.metadata.title}. Disponível em: ${doc.metadata.identifier}. Acesso em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}.`;
    }
  },
  {
    id: "apa",
    name: "APA",
    format: (doc) => {
      const year = new Date(doc.metadata.date).getFullYear();
      return `${doc.metadata.autoridade} (${year}). ${doc.metadata.title}. Retrieved from ${doc.metadata.identifier}`;
    }
  },
  {
    id: "chicago",
    name: "Chicago",
    format: (doc) => {
      const date = new Date(doc.metadata.date);
      const formattedDate = date.toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric"
      });
      return `"${doc.metadata.title}," ${doc.metadata.tipoDocumento}, ${formattedDate}, ${doc.metadata.identifier}.`;
    }
  }
];
const DocumentViewer = ({
  document: document2,
  onClose,
  className = ""
}) => {
  var _a, _b;
  const [content, setContent] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const [selectedCitation, setSelectedCitation] = reactExports.useState("abnt");
  const [showCitationCopied, setShowCitationCopied] = reactExports.useState(false);
  const [crossReferences, setCrossReferences] = reactExports.useState(null);
  const [relatedDocuments, setRelatedDocuments] = reactExports.useState(null);
  const [activeTab, setActiveTab] = reactExports.useState("content");
  reactExports.useEffect(() => {
    const loadDocumentData = () => __async$2(null, null, function* () {
      setLoading(true);
      setError(null);
      try {
        const contentResult = yield lexmlAPI.getDocumentContent(document2.metadata.urn);
        setContent(contentResult);
        lexmlAPI.findCrossReferences(document2.metadata.urn).then((refs) => setCrossReferences(refs)).catch((err) => console.warn("Cross-references failed:", err));
        lexmlAPI.getRelatedDocuments(document2.metadata.urn, 10).then((related) => setRelatedDocuments(related)).catch((err) => console.warn("Related documents failed:", err));
      } catch (err) {
        console.error("Error loading document content:", err);
        setError("Failed to load document content");
      } finally {
        setLoading(false);
      }
    });
    loadDocumentData();
  }, [document2.metadata.urn]);
  const copyCitation = (format) => __async$2(null, null, function* () {
    const citation = format.format(document2);
    try {
      yield navigator.clipboard.writeText(citation);
      setShowCitationCopied(true);
      setTimeout(() => setShowCitationCopied(false), 2e3);
    } catch (err) {
      console.error("Failed to copy citation:", err);
    }
  });
  const formatDate = (dateString) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString("pt-BR", {
        year: "numeric",
        month: "long",
        day: "numeric"
      });
    } catch (e) {
      return dateString;
    }
  };
  const getDocumentTypeColor = (type) => {
    const colors = {
      "Lei": "bg-blue-100 text-blue-800 border-blue-200",
      "Decreto": "bg-green-100 text-green-800 border-green-200",
      "Portaria": "bg-yellow-100 text-yellow-800 border-yellow-200",
      "Resolução": "bg-purple-100 text-purple-800 border-purple-200",
      "Medida Provisória": "bg-red-100 text-red-800 border-red-200"
    };
    return colors[type] || "bg-gray-100 text-gray-800 border-gray-200";
  };
  const isGovernmentSource = (url) => {
    const govDomains = [
      "planalto.gov.br",
      "camara.leg.br",
      "senado.leg.br",
      "in.gov.br",
      "lexml.gov.br",
      ".gov.br"
    ];
    return govDomains.some((domain) => url.includes(domain));
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 ${className}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white rounded-lg max-w-5xl w-full max-h-[95vh] overflow-hidden flex flex-col", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sticky top-0 bg-white border-b border-gray-200 px-6 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `px-3 py-1 text-sm font-medium rounded-full border ${getDocumentTypeColor(document2.metadata.tipoDocumento)}`, children: document2.metadata.tipoDocumento }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-gray-600", children: [
            "📍 ",
            document2.metadata.localidade,
            " | 🏛️ ",
            document2.metadata.autoridade
          ] }),
          isGovernmentSource(document2.metadata.identifier) && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "bg-green-100 text-green-800 px-2 py-1 text-xs rounded-full border border-green-200", children: "✅ Official Government Source" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-xl font-semibold text-gray-900 mb-1", children: document2.metadata.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-gray-600", children: [
          "📅 ",
          formatDate(document2.metadata.date),
          " | 🔗 ",
          document2.metadata.urn
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: onClose,
          className: "ml-4 text-gray-400 hover:text-gray-600 transition-colors",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-6 h-6", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M6 18L18 6M6 6l12 12" }) })
        }
      )
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 overflow-y-auto", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-gray-200 bg-gray-50 px-6 py-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setActiveTab("content"),
            className: `px-3 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === "content" ? "bg-blue-100 text-blue-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`,
            children: "📄 Content"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => setActiveTab("references"),
            className: `px-3 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === "references" ? "bg-blue-100 text-blue-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`,
            children: [
              "🔗 References ",
              ((_a = crossReferences == null ? void 0 : crossReferences.references) == null ? void 0 : _a.length) ? `(${crossReferences.references.length})` : ""
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => setActiveTab("related"),
            className: `px-3 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === "related" ? "bg-blue-100 text-blue-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`,
            children: [
              "📚 Related ",
              ((_b = relatedDocuments == null ? void 0 : relatedDocuments.documents) == null ? void 0 : _b.length) ? `(${relatedDocuments.documents.length})` : ""
            ]
          }
        )
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-6 space-y-6", children: [
        activeTab === "content" && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-blue-50 border border-blue-200 rounded-lg p-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `text-lg ${document2.data_source === "live-api" ? "🔴" : document2.data_source === "cached-api" ? "🟡" : "⚫"}` }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-medium text-blue-900", children: [
                "Data Source: ",
                document2.data_source === "live-api" ? "Live LexML API" : document2.data_source === "cached-api" ? "Cached API Data" : "CSV Fallback Dataset"
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-blue-800", children: document2.data_source === "csv-fallback" ? "This document is from the transport legislation dataset. Full content may be limited." : "This document data is sourced from LexML Brasil, the official Brazilian legal database." })
          ] }),
          document2.metadata.description && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900 mb-2", children: "Description" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-700 leading-relaxed", children: document2.metadata.description })
          ] }),
          document2.metadata.subject.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900 mb-3", children: "Subjects & Keywords" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2", children: document2.metadata.subject.map((subject, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: "bg-gray-100 text-gray-800 px-3 py-1 text-sm rounded-full border border-gray-200",
                children: subject
              },
              index
            )) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900 mb-3", children: "Document Content" }),
            loading && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center py-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-600", children: "Loading document content..." })
            ] }) }),
            error && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-red-50 border border-red-200 rounded-lg p-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-red-500", children: "❌" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-red-800 font-medium", children: "Error Loading Content" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-red-700 mt-1", children: error })
            ] }),
            content && !loading && !error && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
              content.full_text_url ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-green-50 border border-green-200 rounded-lg p-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-green-500", children: "🌐" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-green-800 font-medium", children: "Full Document Available" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-green-700 mb-3", children: "The complete document text is available at the official government source." }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs(
                  "a",
                  {
                    href: content.full_text_url,
                    target: "_blank",
                    rel: "noopener noreferrer",
                    className: "\n                          inline-flex items-center gap-2 px-4 py-2 \n                          bg-green-600 text-white rounded-lg \n                          hover:bg-green-700 transition-colors\n                        ",
                    children: [
                      "📄 View Full Document",
                      /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-4 h-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" }) })
                    ]
                  }
                )
              ] }) : content.note ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-yellow-50 border border-yellow-200 rounded-lg p-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-yellow-500", children: "ℹ️" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-yellow-800 font-medium", children: "Limited Content" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-yellow-700", children: content.note })
              ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-gray-50 border border-gray-200 rounded-lg p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600", children: "Document metadata loaded. Full text content retrieval capabilities are being enhanced. Please use the official source link below." }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-gray-50 border border-gray-200 rounded-lg p-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-medium text-gray-900 mb-3", children: "Document Metadata" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4 text-sm", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "URN:" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block mt-1 p-2 bg-white border rounded font-mono text-xs break-all", children: document2.metadata.urn })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Data Source:" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block mt-1 text-gray-600", children: content.data_source === "api" ? "Live LexML API" : "Fallback Dataset" })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Retrieved:" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block mt-1 text-gray-600", children: new Date(content.retrieved_at).toLocaleString("pt-BR") })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Cached:" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block mt-1 text-gray-600", children: content.cached ? "Yes" : "No" })
                  ] })
                ] })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900 mb-3", children: "Academic Citations" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-gray-50 border border-gray-200 rounded-lg p-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "text-sm font-medium text-gray-700", children: "Format:" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "select",
                  {
                    value: selectedCitation,
                    onChange: (e) => setSelectedCitation(e.target.value),
                    className: "text-sm border border-gray-300 rounded px-2 py-1",
                    children: citationFormats.map((format) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: format.id, children: format.name }, format.id))
                  }
                )
              ] }),
              citationFormats.map((format) => selectedCitation === format.id && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-white border border-gray-300 rounded p-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-sm text-gray-800 break-words", children: format.format(document2) }) }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    onClick: () => copyCitation(format),
                    className: "\n                          px-3 py-1 text-sm bg-blue-600 text-white rounded\n                          hover:bg-blue-700 transition-colors\n                          flex items-center gap-1\n                        ",
                    children: "📋 Copy Citation"
                  }
                )
              ] }, format.id)),
              showCitationCopied && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 text-sm text-green-600", children: "✅ Citation copied to clipboard!" })
            ] })
          ] })
        ] }),
        activeTab === "references" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900", children: "Legal Cross-References" }),
          crossReferences === null ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center py-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-600", children: "Analyzing document for cross-references..." })
          ] }) }) : crossReferences.references.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-gray-50 border border-gray-200 rounded-lg p-6 text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-500 text-lg", children: "📋" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mt-2", children: "No cross-references found in this document." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-500 mt-1", children: "Cross-references include citations to other laws, decrees, articles, and legal provisions." })
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4", children: ["law", "decree", "article", "paragraph"].map((refType) => {
            const refs = crossReferences.references.filter((ref) => ref.type === refType);
            if (refs.length === 0) return null;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white border border-gray-200 rounded-lg p-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { className: "font-medium text-gray-900 mb-3 capitalize", children: [
                refType === "law" ? "⚖️ Laws" : refType === "decree" ? "📜 Decrees" : refType === "article" ? "📄 Articles" : "📝 Paragraphs",
                " (",
                refs.length,
                ")"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-2", children: refs.map((ref, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-gray-50 border border-gray-200 rounded p-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-mono text-sm text-blue-700", children: ref.text }),
                ref.description && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-gray-600 mt-1", children: ref.description }),
                ref.url && /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "a",
                  {
                    href: ref.url,
                    target: "_blank",
                    rel: "noopener noreferrer",
                    className: "text-xs text-blue-600 hover:underline mt-1 inline-block",
                    children: "View Document →"
                  }
                )
              ] }, index)) })
            ] }, refType);
          }) })
        ] }),
        activeTab === "related" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-medium text-gray-900", children: "Related Documents" }),
          relatedDocuments === null ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center py-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-600", children: "Finding related documents..." })
          ] }) }) : relatedDocuments.documents.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-gray-50 border border-gray-200 rounded-lg p-6 text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-500 text-lg", children: "📚" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mt-2", children: "No related documents found." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-500 mt-1", children: "Related documents are found based on similar subjects, document types, and content." })
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-gray-600", children: [
              "Found ",
              relatedDocuments.total_found,
              " related documents (showing top ",
              relatedDocuments.documents.length,
              ")"
            ] }),
            relatedDocuments.documents.map((relatedDoc, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 min-w-0", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `px-2 py-1 text-xs rounded-full ${relatedDoc.metadata.tipoDocumento === "Lei" ? "bg-blue-100 text-blue-800" : relatedDoc.metadata.tipoDocumento === "Decreto" ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"}`, children: relatedDoc.metadata.tipoDocumento }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-gray-500", children: [
                      relatedDoc.metadata.localidade,
                      " | ",
                      relatedDoc.metadata.autoridade
                    ] })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-medium text-gray-900 mb-1 line-clamp-2", children: relatedDoc.metadata.title }),
                  relatedDoc.metadata.description && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-600 line-clamp-2 mb-2", children: relatedDoc.metadata.description }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-gray-500", children: [
                    "📅 ",
                    new Date(relatedDoc.metadata.date).toLocaleDateString("pt-BR")
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "ml-4 flex flex-col gap-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    onClick: () => window.open(relatedDoc.metadata.identifier, "_blank"),
                    className: "text-xs text-blue-600 hover:text-blue-800",
                    children: "View →"
                  }
                ) })
              ] }),
              relatedDoc.metadata.subject.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-1", children: [
                relatedDoc.metadata.subject.slice(0, 3).map((subject, subIndex) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "span",
                  {
                    className: "px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded",
                    children: subject
                  },
                  subIndex
                )),
                relatedDoc.metadata.subject.length > 3 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "px-2 py-1 text-xs text-gray-500", children: [
                  "+",
                  relatedDoc.metadata.subject.length - 3,
                  " more"
                ] })
              ] })
            ] }, index))
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-gray-200 px-6 py-4 bg-gray-50", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "a",
          {
            href: document2.metadata.identifier,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "\n                  px-4 py-2 bg-blue-600 text-white rounded-lg\n                  hover:bg-blue-700 transition-colors\n                  flex items-center gap-2\n                ",
            children: [
              "🌐 Official Source",
              /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "w-4 h-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" }) })
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "\n                px-4 py-2 bg-gray-100 text-gray-700 rounded-lg\n                hover:bg-gray-200 transition-colors\n                flex items-center gap-2\n              ", children: "📄 Export PDF" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: onClose,
          className: "\n                px-4 py-2 bg-gray-600 text-white rounded-lg\n                hover:bg-gray-700 transition-colors\n              ",
          children: "Close"
        }
      )
    ] }) })
  ] }) });
};
var DocumentViewer_default = DocumentViewer;
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
const CacheStatusIndicator = ({
  className = "",
  showDetails = false
}) => {
  const [stats, setStats] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const [showFullStats, setShowFullStats] = reactExports.useState(false);
  reactExports.useEffect(() => {
    const loadStats = () => __async$1(null, null, function* () {
      try {
        setLoading(true);
        const cacheStats = cacheService.getStats();
        setStats(cacheStats);
        setError(null);
      } catch (err) {
        console.error("Failed to load cache stats:", err);
        setError("Failed to load cache stats");
      } finally {
        setLoading(false);
      }
    });
    loadStats();
    const interval = setInterval(loadStats, 3e4);
    return () => clearInterval(interval);
  }, []);
  if (loading) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex items-center gap-2 ${className}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Loading cache status..." })
    ] });
  }
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex items-center gap-2 ${className}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-red-500", children: "🔴" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-red-600", children: error })
    ] });
  }
  if (!stats) return null;
  const getHitRateColor = (rate) => {
    if (rate >= 80) return "text-green-600";
    if (rate >= 60) return "text-yellow-600";
    return "text-red-600";
  };
  const getHitRateEmoji = (rate) => {
    if (rate >= 80) return "🟢";
    if (rate >= 60) return "🟡";
    return "🔴";
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: "flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded",
        onClick: () => setShowFullStats(!showFullStats),
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: getHitRateEmoji(stats.hitRate) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm font-medium text-gray-700", children: [
            "Cache: ",
            stats.hitRate,
            "%"
          ] }),
          showDetails && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-gray-500", children: [
            "(",
            stats.totalItems,
            " items, ",
            stats.memoryUsage,
            "MB)"
          ] }),
          showDetails && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-gray-400", children: showFullStats ? "▼" : "▶" })
        ]
      }
    ),
    showFullStats && showDetails && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "absolute z-50 mt-2 p-4 bg-white border border-gray-200 rounded-lg shadow-lg min-w-80", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-gray-900 mb-3", children: "Cache Performance" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Hit Rate:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: `text-sm font-medium ${getHitRateColor(stats.hitRate)}`, children: [
            stats.hitRate,
            "%"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Miss Rate:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-gray-500", children: [
            stats.missRate,
            "%"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Memory Usage:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-gray-700", children: [
            stats.memoryUsage,
            "MB"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Cached Items:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-700", children: stats.totalItems })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-600", children: "Evictions:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-gray-700", children: stats.evictions })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 pt-3 border-t border-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => {
              cacheService.clear();
              setShowFullStats(false);
            },
            className: "px-3 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200",
            children: "Clear Cache"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => cacheService.prefetchCommonQueries(),
            className: "px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200",
            children: "Prefetch Common"
          }
        )
      ] }) })
    ] })
  ] });
};
var CacheStatusIndicator_default = CacheStatusIndicator;
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
const LexMLSearchContainer = ({
  className = "",
  defaultQuery = "",
  onDocumentSelect
}) => {
  const [filtersCollapsed, setFiltersCollapsed] = reactExports.useState(true);
  const [selectedDocument, setSelectedDocument] = reactExports.useState(null);
  const {
    searchState,
    searchDocuments,
    searchWithCQL,
    loadMoreResults,
    clearResults,
    setFilters,
    apiHealth,
    refreshHealth
  } = useLexMLSearch({
    debounceMs: 500,
    autoSearch: false,
    minQueryLength: 3,
    defaultMaxRecords: 50
  });
  const handleSearch = reactExports.useCallback((query) => __async(null, null, function* () {
    yield searchDocuments(query, searchState.filters);
  }), [searchDocuments, searchState.filters]);
  const handleCQLSearch = reactExports.useCallback((cqlQuery) => __async(null, null, function* () {
    yield searchWithCQL(cqlQuery);
  }), [searchWithCQL]);
  const handleFiltersChange = reactExports.useCallback((newFilters) => {
    setFilters(newFilters);
  }, [setFilters]);
  const handleDocumentClick = reactExports.useCallback((document2) => {
    setSelectedDocument(document2);
    onDocumentSelect == null ? void 0 : onDocumentSelect(document2);
  }, [onDocumentSelect]);
  const quickSearches = [
    { label: "Transport Laws", query: 'tipoDocumento exact "Lei" AND (title any "transporte" OR description any "transporte")' },
    { label: "Federal Decrees", query: 'tipoDocumento exact "Decreto" AND autoridade exact "federal"' },
    { label: "Recent Legislation", query: 'date >= "2020"' },
    { label: "São Paulo Laws", query: 'localidade any "sao.paulo"' },
    { label: "Urban Mobility", query: 'title any "mobilidade urbana" OR description any "mobilidade urbana"' }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `max-w-7xl mx-auto p-4 space-y-6 ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-3xl font-bold text-gray-900 mb-2", children: "LexML Brasil Legal Search" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 max-w-2xl mx-auto", children: "Real-time access to Brazil's complete legislative database. Search millions of laws, decrees, and legal documents with advanced academic research tools." })
    ] }),
    apiHealth && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-white border border-gray-200 rounded-lg p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `text-lg ${apiHealth.is_healthy ? "🟢" : "🔴"}`, children: apiHealth.is_healthy ? "✅" : "❌" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm font-medium text-gray-700", children: [
            "API Status: ",
            apiHealth.is_healthy ? "Healthy" : "Unavailable"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-gray-500", children: [
              "Response time: ",
              apiHealth.response_time_ms.toFixed(0),
              "ms | Success rate: ",
              apiHealth.success_rate.toFixed(1),
              "%"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(CacheStatusIndicator_default, { showDetails: true })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: refreshHealth,
          className: "text-sm text-blue-600 hover:text-blue-800",
          children: "Refresh Status"
        }
      )
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white border border-gray-200 rounded-lg p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        LexMLSearchBar_default,
        {
          onSearch: handleSearch,
          onCQLSearch: handleCQLSearch,
          initialValue: defaultQuery,
          isLoading: searchState.isLoading,
          showAdvanced: true,
          className: "mb-6"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-medium text-gray-700 mb-3", children: "Quick Searches:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2", children: quickSearches.map((search, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => handleCQLSearch(search.query),
            className: "\n                  px-3 py-2 text-sm bg-gray-100 text-gray-700 rounded-lg\n                  hover:bg-gray-200 focus:ring-2 focus:ring-blue-500\n                  transition-colors duration-200\n                ",
            children: search.label
          },
          index
        )) })
      ] }),
      (searchState.query || searchState.results.length > 0) && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-4 p-3 bg-gray-50 rounded-lg", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between text-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-600", children: searchState.query && `Query: "${searchState.query}"` }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
          searchState.searchTime > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-gray-500", children: [
            "⚡ ",
            searchState.searchTime.toFixed(0),
            "ms"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: clearResults,
              className: "text-red-600 hover:text-red-800",
              children: "Clear"
            }
          )
        ] })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      LexMLFilters_default,
      {
        filters: searchState.filters,
        onFiltersChange: handleFiltersChange,
        isCollapsed: filtersCollapsed,
        onToggleCollapse: () => setFiltersCollapsed(!filtersCollapsed)
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SearchResults_default,
      {
        documents: searchState.results,
        dataSource: searchState.dataSource,
        apiStatus: searchState.apiStatus,
        searchTime: searchState.searchTime,
        resultCount: searchState.resultCount,
        totalAvailable: searchState.totalAvailable,
        isLoading: searchState.isLoading,
        hasNextPage: searchState.hasNextPage,
        onLoadMore: loadMoreResults,
        onDocumentClick: handleDocumentClick
      }
    ),
    selectedDocument && /* @__PURE__ */ jsxRuntimeExports.jsx(
      DocumentViewer_default,
      {
        document: selectedDocument,
        onClose: () => setSelectedDocument(null)
      }
    )
  ] });
};
var LexMLSearchContainer_default = LexMLSearchContainer;
const LexMLSearchPage = ({ className = "" }) => {
  const handleDocumentSelect = (document2) => {
    console.log("Document selected:", document2);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `min-h-screen bg-gray-50 ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("header", { className: "bg-white shadow-sm border-b border-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-w-7xl mx-auto px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-bold text-gray-900", children: "Monitor Legislativo v4" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mt-1", children: "Real-time Legislative Search powered by LexML Brasil" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { className: "flex items-center gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            href: "/",
            className: "text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium",
            children: "Dashboard"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            href: "/search",
            className: "bg-blue-600 text-white px-3 py-2 rounded-md text-sm font-medium",
            children: "Search"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            href: "/about",
            className: "text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium",
            children: "About"
          }
        )
      ] })
    ] }) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "py-8", children: /* @__PURE__ */ jsxRuntimeExports.jsx(LexMLSearchContainer_default, { onDocumentSelect: handleDocumentSelect }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "bg-white border-t border-gray-200 mt-16", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-w-7xl mx-auto px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between text-sm text-gray-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Monitor Legislativo v4 - Academic Research Platform" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1", children: "Data provided by LexML Brasil (FREE government service)" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex items-center gap-1", children: "🚀 Real-time API" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex items-center gap-1", children: "⚫ CSV Fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex items-center gap-1", children: "🏛️ Official Sources" })
      ] })
    ] }) }) })
  ] });
};
var LexMLSearchPage_default = LexMLSearchPage;
export {
  LexMLSearchPage,
  LexMLSearchPage_default as default
};
