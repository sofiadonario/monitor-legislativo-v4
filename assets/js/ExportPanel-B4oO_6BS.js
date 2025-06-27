import { j as jsxRuntimeExports } from "./index-BYGq6Ng0.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { b as buildApiUrl, A as API_CONFIG, C as CORS_CONFIG } from "./api-DW14Y_8v.js";
import { g as getDefaultExportFromCjs } from "./react-vendor-CSPBeBBz.js";
import { r as requirePapaparse_min, h as html2canvas } from "./utils-Cs_fMHvp.js";
const exportToBibTeX = (documents) => {
  const entries = documents.map((doc) => {
    const authors = doc.source.includes("Câmara") ? "Brasil. Câmara dos Deputados" : doc.source.includes("Senado") ? "Brasil. Senado Federal" : doc.source.includes("LexML") ? "Brasil. LexML" : "Brasil";
    const year = new Date(doc.date).getFullYear();
    const key = `${doc.type}${doc.number.replace(/[^0-9]/g, "")}${year}`;
    return `@legislation{${key},
  title={${doc.title}},
  author={${authors}},
  year={${year}},
  type={${doc.type}},
  number={${doc.number}},
  institution={${doc.source}},
  url={${doc.url || ""}},
  note={Accessed: ${(/* @__PURE__ */ new Date()).toLocaleDateString("en-CA")}}
}`;
  }).join("\n\n");
  const bibTeX = `% BibTeX export from Brazilian Transport Legislation Monitor
% Generated: ${(/* @__PURE__ */ new Date()).toISOString()}
% Total entries: ${documents.length}

${entries}`;
  const blob = new Blob([bibTeX], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `transport-legislation-${(/* @__PURE__ */ new Date()).toISOString()}.bib`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
var __defProp$4 = Object.defineProperty;
var __defProps$3 = Object.defineProperties;
var __getOwnPropDescs$3 = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols$4 = Object.getOwnPropertySymbols;
var __hasOwnProp$4 = Object.prototype.hasOwnProperty;
var __propIsEnum$4 = Object.prototype.propertyIsEnumerable;
var __defNormalProp$4 = (obj, key, value) => key in obj ? __defProp$4(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues$4 = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp$4.call(b, prop))
      __defNormalProp$4(a, prop, b[prop]);
  if (__getOwnPropSymbols$4)
    for (var prop of __getOwnPropSymbols$4(b)) {
      if (__propIsEnum$4.call(b, prop))
        __defNormalProp$4(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps$3 = (a, b) => __defProps$3(a, __getOwnPropDescs$3(b));
var __publicField$1 = (obj, key, value) => __defNormalProp$4(obj, typeof key !== "symbol" ? key + "" : key, value);
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
class LocalCache {
  constructor(options) {
    __publicField$1(this, "prefix", "legislativo_");
    __publicField$1(this, "maxAge", 36e5);
    __publicField$1(this, "maxSize", 5 * 1024 * 1024);
    __publicField$1(this, "version", "1.0.0");
    __publicField$1(this, "stats", {
      hits: 0,
      misses: 0,
      itemCount: 0,
      totalSize: 0
    });
    if (options == null ? void 0 : options.prefix) this.prefix = options.prefix;
    if (options == null ? void 0 : options.maxAge) this.maxAge = options.maxAge;
    if (options == null ? void 0 : options.maxSize) this.maxSize = options.maxSize;
    if (options == null ? void 0 : options.version) this.version = options.version;
    this.updateStats();
    this.cleanup();
  }
  /**
   * Set item in cache
   */
  set(key, value, ttl = this.maxAge) {
    try {
      const item = {
        value,
        expires: Date.now() + ttl,
        version: this.version,
        size: this.estimateSize(value)
      };
      const serialized = JSON.stringify(item);
      const fullKey = this.prefix + key;
      if (serialized.length > this.maxSize) {
        console.warn(`Cache item too large: ${key}`);
        return false;
      }
      const currentSize = this.getTotalSize();
      if (currentSize + serialized.length > this.maxSize) {
        this.evictOldest(serialized.length);
      }
      localStorage.setItem(fullKey, serialized);
      this.updateStats();
      return true;
    } catch (e) {
      if (e instanceof Error && e.name === "QuotaExceededError") {
        console.warn("LocalStorage quota exceeded, cleaning up...");
        this.cleanup();
        try {
          const item = {
            value,
            expires: Date.now() + ttl,
            version: this.version
          };
          localStorage.setItem(this.prefix + key, JSON.stringify(item));
          return true;
        } catch (e2) {
          return false;
        }
      }
      console.error("Cache set error:", e);
      return false;
    }
  }
  /**
   * Get item from cache
   */
  get(key) {
    try {
      const fullKey = this.prefix + key;
      const item = localStorage.getItem(fullKey);
      if (!item) {
        this.stats.misses++;
        return null;
      }
      const data = JSON.parse(item);
      if (data.expires < Date.now()) {
        localStorage.removeItem(fullKey);
        this.stats.misses++;
        this.updateStats();
        return null;
      }
      if (data.version !== this.version) {
        localStorage.removeItem(fullKey);
        this.stats.misses++;
        this.updateStats();
        return null;
      }
      this.stats.hits++;
      return data.value;
    } catch (e) {
      console.error("Cache get error:", e);
      this.stats.misses++;
      return null;
    }
  }
  /**
   * Get or fetch pattern
   */
  getOrFetch(_0, _1) {
    return __async$3(this, arguments, function* (key, fetchFn, ttl = this.maxAge) {
      const cached = this.get(key);
      if (cached !== null) {
        return cached;
      }
      try {
        const data = yield fetchFn();
        this.set(key, data, ttl);
        return data;
      } catch (error) {
        const staleKey = `stale_${key}`;
        const stale = this.get(staleKey);
        if (stale !== null) {
          console.warn("Using stale cache for:", key);
          return stale;
        }
        throw error;
      }
    });
  }
  /**
   * Remove item from cache
   */
  remove(key) {
    localStorage.removeItem(this.prefix + key);
    this.updateStats();
  }
  /**
   * Clear all cache items with this prefix
   */
  clear() {
    const keys = this.getAllKeys();
    keys.forEach((key) => localStorage.removeItem(key));
    this.updateStats();
  }
  /**
   * Clean up expired items
   */
  cleanup() {
    const now = Date.now();
    const keys = this.getAllKeys();
    keys.forEach((key) => {
      try {
        const item = localStorage.getItem(key);
        if (item) {
          const data = JSON.parse(item);
          if (data.expires < now || data.version !== this.version) {
            localStorage.removeItem(key);
          }
        }
      } catch (e) {
        localStorage.removeItem(key);
      }
    });
    this.updateStats();
  }
  /**
   * Get cache statistics
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? this.stats.hits / total * 100 : 0;
    return __spreadProps$3(__spreadValues$4({}, this.stats), {
      hitRate
    });
  }
  /**
   * Batch operations
   */
  getBatch(keys) {
    return __async$3(this, null, function* () {
      const results = /* @__PURE__ */ new Map();
      keys.forEach((key) => {
        results.set(key, this.get(key));
      });
      return results;
    });
  }
  setBatch(items) {
    items.forEach((item, key) => {
      this.set(key, item.value, item.ttl || this.maxAge);
    });
  }
  /**
   * Cache warming
   */
  warm(keys, fetchFn) {
    return __async$3(this, null, function* () {
      const promises = keys.map((key) => __async$3(this, null, function* () {
        const cached = this.get(key);
        if (cached === null) {
          try {
            const data = yield fetchFn(key);
            this.set(key, data);
          } catch (e) {
            console.error(`Failed to warm cache for key: ${key}`, e);
          }
        }
      }));
      yield Promise.all(promises);
    });
  }
  /**
   * Private helper methods
   */
  getAllKeys() {
    return Object.keys(localStorage).filter((key) => key.startsWith(this.prefix));
  }
  getTotalSize() {
    let total = 0;
    this.getAllKeys().forEach((key) => {
      const item = localStorage.getItem(key);
      if (item) {
        total += item.length;
      }
    });
    return total;
  }
  estimateSize(value) {
    try {
      return JSON.stringify(value).length;
    } catch (e) {
      return 0;
    }
  }
  evictOldest(requiredSpace) {
    const items = [];
    this.getAllKeys().forEach((key) => {
      try {
        const item = localStorage.getItem(key);
        if (item) {
          const data = JSON.parse(item);
          items.push({
            key,
            expires: data.expires || 0,
            size: item.length
          });
        }
      } catch (e) {
        localStorage.removeItem(key);
      }
    });
    items.sort((a, b) => a.expires - b.expires);
    let freedSpace = 0;
    for (const item of items) {
      if (freedSpace >= requiredSpace) break;
      localStorage.removeItem(item.key);
      freedSpace += item.size;
    }
  }
  updateStats() {
    const keys = this.getAllKeys();
    this.stats.itemCount = keys.length;
    this.stats.totalSize = this.getTotalSize();
  }
}
const localCache = new LocalCache({
  prefix: "legislativo_",
  maxAge: 36e5,
  // 1 hour
  maxSize: 5 * 1024 * 1024,
  // 5MB
  version: "1.0.0"
});
const cacheUtils = {
  /**
   * Generate cache key from parameters
   */
  generateKey(prefix, params) {
    const sorted = Object.keys(params).sort().map((key) => `${key}:${params[key]}`).join("_");
    return `${prefix}_${sorted}`;
  },
  /**
   * Cache API response
   */
  cacheAPIResponse(url, options, ttl = 9e5) {
    return __async$3(this, null, function* () {
      const cacheKey = cacheUtils.generateKey("api", { url, method: (options == null ? void 0 : options.method) || "GET" });
      return localCache.getOrFetch(
        cacheKey,
        () => __async$3(null, null, function* () {
          const response = yield fetch(url, options);
          if (!response.ok) {
            throw new Error(`API error: ${response.statusText}`);
          }
          return response.json();
        }),
        ttl
      );
    });
  },
  /**
   * Clear API cache
   */
  clearAPICache() {
    const keys = Object.keys(localStorage).filter((key) => key.startsWith("legislativo_api_"));
    keys.forEach((key) => localStorage.removeItem(key));
  }
};
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
var __objRest = (source, exclude) => {
  var target = {};
  for (var prop in source)
    if (__hasOwnProp$3.call(source, prop) && exclude.indexOf(prop) < 0)
      target[prop] = source[prop];
  if (source != null && __getOwnPropSymbols$3)
    for (var prop of __getOwnPropSymbols$3(source)) {
      if (exclude.indexOf(prop) < 0 && __propIsEnum$3.call(source, prop))
        target[prop] = source[prop];
    }
  return target;
};
var __publicField = (obj, key, value) => __defNormalProp$3(obj, typeof key !== "symbol" ? key + "" : key, value);
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
const CACHE_CONFIG = {
  "/api/v1/search": { ttl: 9e5, priority: "high" },
  "/api/v1/sources": { ttl: 864e5, priority: "low" },
  "/api/v1/export": { ttl: 18e5, priority: "medium" }
};
class CachedFetch {
  constructor() {
    __publicField(this, "abortControllers", /* @__PURE__ */ new Map());
    __publicField(this, "pendingRequests", /* @__PURE__ */ new Map());
  }
  /**
   * Enhanced fetch with caching support
   */
  fetch(_0) {
    return __async$2(this, arguments, function* (url, options = {}) {
      var _b;
      const _a = options, {
        ttl,
        retry = 3,
        timeout = API_CONFIG.timeout,
        fallbackToCache = true
      } = _a, fetchOptions = __objRest(_a, [
        "ttl",
        "retry",
        "timeout",
        "fallbackToCache"
      ]);
      const fullUrl = url.startsWith("http") ? url : buildApiUrl(url);
      const finalOptions = __spreadProps$2(__spreadValues$3(__spreadValues$3({}, CORS_CONFIG), fetchOptions), {
        headers: __spreadValues$3(__spreadValues$3({}, API_CONFIG.headers), fetchOptions.headers)
      });
      const cacheKey = this.generateCacheKey(fullUrl, finalOptions);
      const pending = this.pendingRequests.get(cacheKey);
      if (pending) {
        return pending;
      }
      if (!finalOptions.method || finalOptions.method === "GET") {
        const cached = localCache.get(cacheKey);
        if (cached !== null) {
          if ("headers" in cached && ((_b = cached.headers) == null ? void 0 : _b["X-Cache"])) {
            console.log(`Cache HIT: ${fullUrl}`);
          }
          return cached;
        }
      }
      const abortController = new AbortController();
      this.abortControllers.set(cacheKey, abortController);
      const timeoutId = setTimeout(() => {
        abortController.abort();
      }, timeout);
      const fetchPromise = this.fetchWithRetry(fullUrl, __spreadProps$2(__spreadValues$3({}, finalOptions), {
        signal: abortController.signal
      }), retry).then((response) => __async$2(this, null, function* () {
        clearTimeout(timeoutId);
        const cacheStatus = response.headers.get("X-Cache") || "MISS";
        response.headers.get("X-Cache-Time");
        console.log(`API ${cacheStatus}: ${fullUrl}`);
        const data = yield response.json();
        if (response.ok && (!finalOptions.method || finalOptions.method === "GET")) {
          const cacheTTL = ttl || this.getTTLForURL(fullUrl);
          localCache.set(cacheKey, data, cacheTTL);
          localCache.set(`stale_${cacheKey}`, data, cacheTTL * 2);
        }
        return data;
      })).catch((error) => __async$2(this, null, function* () {
        clearTimeout(timeoutId);
        if (fallbackToCache && (!finalOptions.method || finalOptions.method === "GET")) {
          const cached = localCache.get(cacheKey);
          if (cached !== null) {
            console.warn(`Using cached data due to error: ${fullUrl}`);
            return cached;
          }
          const stale = localCache.get(`stale_${cacheKey}`);
          if (stale !== null) {
            console.warn(`Using stale cache due to error: ${fullUrl}`);
            return stale;
          }
        }
        throw error;
      })).finally(() => {
        this.abortControllers.delete(cacheKey);
        this.pendingRequests.delete(cacheKey);
      });
      this.pendingRequests.set(cacheKey, fetchPromise);
      return fetchPromise;
    });
  }
  /**
   * Fetch with retry logic
   */
  fetchWithRetry(url, options, retries) {
    return __async$2(this, null, function* () {
      let lastError = null;
      for (let i = 0; i <= retries; i++) {
        try {
          const response = yield fetch(url, options);
          if (response.status >= 500 && i < retries) {
            yield this.delay(Math.min(1e3 * Math.pow(2, i), 1e4));
            continue;
          }
          return response;
        } catch (error) {
          lastError = error;
          if (error instanceof Error && error.name === "AbortError") {
            throw error;
          }
          if (i < retries) {
            yield this.delay(Math.min(1e3 * Math.pow(2, i), 1e4));
            continue;
          }
        }
      }
      throw lastError || new Error("Fetch failed");
    });
  }
  /**
   * Generate cache key from URL and options
   */
  generateCacheKey(url, options) {
    const key = {
      url,
      method: options.method || "GET",
      body: options.body ? JSON.stringify(options.body) : void 0
    };
    return cacheUtils.generateKey("fetch", key);
  }
  /**
   * Get TTL for URL based on configuration
   */
  getTTLForURL(url) {
    const urlPath = new URL(url, window.location.origin).pathname;
    const config = CACHE_CONFIG[urlPath];
    if (config) {
      return config.ttl;
    }
    for (const [pattern, config2] of Object.entries(CACHE_CONFIG)) {
      if (urlPath.startsWith(pattern)) {
        return config2.ttl;
      }
    }
    return 9e5;
  }
  /**
   * Delay helper
   */
  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  /**
   * Cancel pending request
   */
  cancel(url) {
    const cacheKey = this.generateCacheKey(url, {});
    const controller = this.abortControllers.get(cacheKey);
    if (controller) {
      controller.abort();
    }
  }
  /**
   * Prefetch URLs
   */
  prefetch(urls) {
    return __async$2(this, null, function* () {
      const promises = urls.map(
        (url) => this.fetch(url, { fallbackToCache: true }).catch(() => {
        })
      );
      yield Promise.all(promises);
    });
  }
  /**
   * Clear cache for specific patterns
   */
  clearCache(pattern) {
    if (pattern) {
      const keys = Object.keys(localStorage).filter((key) => key.includes(pattern));
      keys.forEach((key) => localStorage.removeItem(key));
    } else {
      cacheUtils.clearAPICache();
    }
  }
  /**
   * Get cache statistics
   */
  getCacheStats() {
    return localCache.getStats();
  }
}
const cachedFetch = new CachedFetch();
const fetchJSON = (url, options) => cachedFetch.fetch(url, options);
var papaparse_minExports = /* @__PURE__ */ requirePapaparse_min();
const Papa = /* @__PURE__ */ getDefaultExportFromCjs(papaparse_minExports);
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
const exportToCSV = (documents, options) => {
  const csvData = documents.map((doc) => __spreadValues$2({
    "ID": doc.id,
    "Título": doc.title,
    "Tipo": doc.type,
    "Número": doc.number,
    "Data": doc.date,
    "Estado": doc.state || "",
    "Município": doc.municipality || "",
    "Resumo": doc.summary,
    "Palavras-chave": doc.keywords.join(", ")
  }, options.includeMetadata && {
    "Fonte": doc.source,
    "Citação": doc.citation,
    "URL": doc.url || ""
  }));
  const csv = Papa.unparse(csvData);
  downloadFile(csv, `transport-legislation-data-${(/* @__PURE__ */ new Date()).toISOString()}.csv`, "text/csv");
};
const exportToXML = (documents, options) => {
  const xmlHeader = '<?xml version="1.0" encoding="UTF-8"?>\n';
  const rootStart = "<documentos_legislativos>\n";
  const metadata = `  <metadata>
    <data_exportacao>${(/* @__PURE__ */ new Date()).toISOString()}</data_exportacao>
    <total_documentos>${documents.length}</total_documentos>
  </metadata>
`;
  const documentsXML = documents.map((doc) => {
    const keywords = doc.keywords.map((k) => `      <palavra_chave>${escapeXML(k)}</palavra_chave>`).join("\n");
    return `  <documento>
    <id>${doc.id}</id>
    <titulo>${escapeXML(doc.title)}</titulo>
    <tipo>${doc.type}</tipo>
    <numero>${escapeXML(doc.number)}</numero>
    <data>${doc.date}</data>
    ${doc.state ? `<estado>${doc.state}</estado>` : ""}
    ${doc.municipality ? `<municipio>${escapeXML(doc.municipality)}</municipio>` : ""}
    <resumo>${escapeXML(doc.summary)}</resumo>
    <palavras_chave>
${keywords}
    </palavras_chave>
    ${options.includeMetadata ? `<metadados>
      <fonte>${escapeXML(doc.source)}</fonte>
      <citacao>${escapeXML(doc.citation)}</citacao>
      ${doc.url ? `<url>${escapeXML(doc.url)}</url>` : ""}
    </metadados>` : ""}
  </documento>`;
  }).join("\n");
  const rootEnd = "\n</documentos_legislativos>";
  const xml = xmlHeader + rootStart + metadata + documentsXML + rootEnd;
  downloadFile(xml, `transport-legislation-data-${(/* @__PURE__ */ new Date()).toISOString()}.xml`, "application/xml");
};
const exportToHTML = (documents, options) => {
  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Dados Legislativos</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2196F3;
            margin: 0;
        }
        .summary {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .document {
            border: 1px solid #ddd;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 5px;
            background: #fafafa;
        }
        .document h3 {
            color: #1976D2;
            margin-top: 0;
        }
        .doc-meta {
            background: #fff;
            padding: 10px;
            border-left: 4px solid #4CAF50;
            margin: 10px 0;
        }
        .keywords {
            background: #f0f0f0;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
            margin: 2px;
            font-size: 0.9em;
        }
        .citation {
            background: #fff3e0;
            padding: 10px;
            border-left: 4px solid #FF9800;
            margin-top: 10px;
            font-style: italic;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Transport Legislation Academic Report</h1>
            <p>Brazilian Transport Legislation Monitor - Academic Research Platform</p>
            <p>Gerado em: ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  })}</p>
        </div>
        
        <div class="summary">
            <h2>Resumo da Pesquisa</h2>
            <p><strong>Total de documentos encontrados:</strong> ${documents.length}</p>
            <p><strong>Estados com legislação:</strong> ${[...new Set(documents.filter((d) => d.state).map((d) => d.state))].length}</p>
            <p><strong>Tipos de documentos:</strong> ${[...new Set(documents.map((d) => d.type))].join(", ")}</p>
            <p><strong>Período:</strong> ${getDateRange(documents)}</p>
        </div>
        
        <div class="documents">
            ${documents.map((doc, index) => `
                <div class="document">
                    <h3>${index + 1}. ${escapeXML(doc.title)}</h3>
                    
                    <div class="doc-meta">
                        <strong>Tipo:</strong> ${doc.type.charAt(0).toUpperCase() + doc.type.slice(1)} | 
                        <strong>Número:</strong> ${escapeXML(doc.number)} | 
                        <strong>Data:</strong> ${new Date(doc.date).toLocaleDateString("pt-BR")}
                        ${doc.state ? ` | <strong>Estado:</strong> ${doc.state}` : ""}
                        ${doc.municipality ? ` | <strong>Município:</strong> ${escapeXML(doc.municipality)}` : ""}
                    </div>
                    
                    <p><strong>Resumo:</strong> ${escapeXML(doc.summary)}</p>
                    
                    <div>
                        <strong>Palavras-chave:</strong><br>
                        ${doc.keywords.map((keyword) => `<span class="keywords">${escapeXML(keyword)}</span>`).join(" ")}
                    </div>
                    
                    ${options.includeMetadata ? `
                        <div class="citation">
                            <strong>Citação acadêmica:</strong><br>
                            ${escapeXML(doc.citation)}
                            ${doc.url ? `<br><strong>URL:</strong> <a href="${doc.url}" target="_blank">${doc.url}</a>` : ""}
                        </div>
                    ` : ""}
                </div>
            `).join("")}
        </div>
        
        <div class="footer">
            <p><strong>Citação sugerida para esta pesquisa:</strong></p>
            <p>Academic Transport Legislation Monitor. Brazilian transport legislation georeferenced data. 
               Exportado em ${(/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR")}. 
               Disponível em: [URL da aplicação].</p>
            <p><em>Este relatório foi gerado automaticamente. Sempre verifique as fontes originais.</em></p>
        </div>
    </div>
</body>
</html>`;
  downloadFile(html, `transport-legislation-report-${(/* @__PURE__ */ new Date()).toISOString()}.html`, "text/html");
};
const escapeXML = (str) => {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
};
const getDateRange = (documents) => {
  if (documents.length === 0) return "N/A";
  const dates = documents.map((doc) => new Date(doc.date));
  const minDate = new Date(Math.min.apply(null, dates));
  const maxDate = new Date(Math.max.apply(null, dates));
  return `${minDate.toLocaleDateString("pt-BR")} a ${maxDate.toLocaleDateString("pt-BR")}`;
};
const downloadFile = (content, filename, mimeType) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};
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
const exportMapToPNG = (..._0) => __async$1(null, [..._0], function* (options = {}) {
  const {
    quality = 0.9,
    scale = 2,
    includeControls = false,
    includeLegend = true,
    backgroundColor = "#ffffff",
    filename = "legislative-map"
  } = options;
  try {
    const mapContainer = document.querySelector(".map-wrapper");
    if (!mapContainer) {
      throw new Error("Map container not found");
    }
    const controls = mapContainer.querySelectorAll(".map-controls");
    const controlsDisplay = [];
    if (!includeControls) {
      controls.forEach((control, index) => {
        const element = control;
        controlsDisplay[index] = element.style.display;
        element.style.display = "none";
      });
    }
    const legend = mapContainer.querySelector(".map-legend");
    let legendDisplay = "";
    if (!includeLegend && legend) {
      legendDisplay = legend.style.display;
      legend.style.display = "none";
    }
    const canvasOptions = {
      allowTaint: true,
      useCORS: true,
      scale,
      backgroundColor,
      width: mapContainer.offsetWidth,
      height: mapContainer.offsetHeight,
      logging: false,
      removeContainer: false,
      imageTimeout: 15e3,
      onclone: (clonedDoc) => {
        const clonedContainer = clonedDoc.querySelector(".map-wrapper");
        if (clonedContainer) {
          clonedContainer.style.transform = "none";
          clonedContainer.style.position = "static";
        }
      }
    };
    const canvas = yield html2canvas(mapContainer, canvasOptions);
    if (!includeControls) {
      controls.forEach((control, index) => {
        const element = control;
        element.style.display = controlsDisplay[index] || "";
      });
    }
    if (!includeLegend && legend) {
      legend.style.display = legendDisplay;
    }
    const timestamp = (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace(/:/g, "-");
    const finalFilename = `${filename}-${timestamp}.png`;
    canvas.toBlob((blob) => {
      if (blob) {
        downloadBlob(blob, finalFilename);
      } else {
        throw new Error("Failed to create image blob");
      }
    }, "image/png", quality);
  } catch (error) {
    console.error("Map export failed:", error);
    throw new Error(`Failed to export map: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
});
const exportMapWithMetadata = (_0, _1, ..._2) => __async$1(null, [_0, _1, ..._2], function* (documents, selectedState, options = {}) {
  const {
    filename = "legislative-map-with-data"
  } = options;
  try {
    const overlay = createMetadataOverlay(documents, selectedState);
    const mapContainer = document.querySelector(".map-wrapper");
    if (!mapContainer) {
      throw new Error("Map container not found");
    }
    mapContainer.appendChild(overlay);
    try {
      yield exportMapToPNG(__spreadProps$1(__spreadValues$1({}, options), { filename }));
    } finally {
      mapContainer.removeChild(overlay);
    }
  } catch (error) {
    console.error("Map export with metadata failed:", error);
    throw error;
  }
});
const createMetadataOverlay = (documents, selectedState) => {
  const overlay = document.createElement("div");
  overlay.className = "map-export-overlay";
  overlay.style.cssText = `
    position: absolute;
    top: 10px;
    left: 10px;
    background: rgba(255, 255, 255, 0.95);
    padding: 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.4;
    max-width: 300px;
    z-index: 1000;
    border: 1px solid #e0e0e0;
  `;
  const title = document.createElement("h3");
  title.textContent = "Monitor Legislativo de Transportes";
  title.style.cssText = `
    margin: 0 0 12px 0;
    font-size: 16px;
    font-weight: 600;
    color: #2196F3;
  `;
  const stats = document.createElement("div");
  const currentDate = (/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR");
  stats.innerHTML = `
    <div style="margin-bottom: 8px;"><strong>Data de exportação:</strong> ${currentDate}</div>
    <div style="margin-bottom: 8px;"><strong>Documentos encontrados:</strong> ${documents.length}</div>
    ${selectedState ? `<div style="margin-bottom: 8px;"><strong>Estado selecionado:</strong> ${selectedState}</div>` : ""}
    <div style="margin-bottom: 8px;"><strong>Fonte:</strong> Dados Abertos do Governo Federal</div>
    <div style="font-size: 12px; color: #666; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e0e0e0;">
      Plataforma Acadêmica de Pesquisa<br>
      Legislação de Transportes do Brasil
    </div>
  `;
  overlay.appendChild(title);
  overlay.appendChild(stats);
  return overlay;
};
const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 100);
};
const isMapExportSupported = () => {
  var _a;
  try {
    const hasCanvas = !!document.createElement("canvas").getContext;
    const hasBlob = !!window.Blob;
    const hasCreateObjectURL = !!((_a = window.URL) == null ? void 0 : _a.createObjectURL);
    return hasCanvas && hasBlob && hasCreateObjectURL;
  } catch (e) {
    return false;
  }
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
const ExportPanel = ({
  isOpen,
  onClose,
  documents,
  id
}) => {
  const [exportFormat, setExportFormat] = reactExports.useState("csv");
  const [includeMap, setIncludeMap] = reactExports.useState(false);
  const [includeMetadata, setIncludeMetadata] = reactExports.useState(true);
  const [exportStatus, setExportStatus] = reactExports.useState("idle");
  const [dateRange, setDateRange] = reactExports.useState({
    from: "",
    to: ""
  });
  const generateCacheKey = reactExports.useCallback((format, options) => {
    const queryParams = {
      format,
      documents: documents.map((d) => d.id).sort(),
      includeMap: options.includeMap,
      includeMetadata: options.includeMetadata,
      dateRange: options.dateRange
    };
    return cacheUtils.generateKey("export", queryParams);
  }, [documents]);
  const downloadFile2 = reactExports.useCallback((content, filename) => {
    const blob = content instanceof Blob ? content : new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);
  const handleExport = () => __async(null, null, function* () {
    const options = {
      format: exportFormat,
      includeMap,
      includeMetadata,
      dateRange: dateRange.from || dateRange.to ? dateRange : void 0
    };
    try {
      const cacheKey = generateCacheKey(exportFormat, options);
      setExportStatus("checking");
      const cached = localCache.get(cacheKey);
      if (cached) {
        console.log("Using cached export");
        const filename2 = `monitor-legislativo-${exportFormat}-${Date.now()}.${exportFormat}`;
        downloadFile2(cached, filename2);
        setExportStatus("ready");
        return;
      }
      try {
        const serverCached = yield fetchJSON(`/api/v1/export/cached/${encodeURIComponent(cacheKey)}`);
        if (serverCached && serverCached.content) {
          console.log("Using server cached export");
          localCache.set(cacheKey, serverCached.content, 36e5);
          const filename2 = `monitor-legislativo-${exportFormat}-${Date.now()}.${exportFormat}`;
          downloadFile2(serverCached.content, filename2);
          setExportStatus("ready");
          return;
        }
      } catch (error) {
        console.log("No server cache available, generating fresh export");
      }
      setExportStatus("generating");
      let filteredDocuments = documents;
      if (options.dateRange) {
        filteredDocuments = documents.filter((doc) => {
          if (options.dateRange.from && doc.date < options.dateRange.from) return false;
          if (options.dateRange.to && doc.date > options.dateRange.to) return false;
          return true;
        });
      }
      let exportContent = null;
      switch (exportFormat) {
        case "csv":
          exportContent = exportToCSV(filteredDocuments, options);
          break;
        case "xml":
          exportContent = exportToXML(filteredDocuments, options);
          break;
        case "html":
          exportContent = exportToHTML(filteredDocuments, options);
          break;
        case "bibtex":
          exportContent = exportToBibTeX(filteredDocuments);
          break;
        case "png":
          if (includeMetadata) {
            yield exportMapWithMetadata(filteredDocuments, void 0, {
              format: "png",
              includeControls: false,
              includeLegend: true
            });
          } else {
            yield exportMapToPNG({
              format: "png",
              includeControls: false,
              includeLegend: true
            });
          }
          break;
      }
      if (exportContent) {
        const filename2 = `monitor-legislativo-${exportFormat}-${Date.now()}.${exportFormat}`;
        downloadFile2(exportContent, filename2);
      }
      setExportStatus("ready");
    } catch (error) {
      console.error("Export failed:", error);
      setExportStatus("idle");
      alert("Erro ao exportar dados. Tente novamente.");
    }
  });
  if (!isOpen) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id, className: "export-panel-overlay", role: "dialog", "aria-modal": "true", "aria-labelledby": "export-panel-title", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-panel", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "export-panel-title", children: "Exportar Dados" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "close-btn", onClick: onClose, "aria-label": "Fechar", children: "✕" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-content", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "export-summary", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: documents.length }),
        " documentos selecionados para exportação"
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Formato de Exportação" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "format-options", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "radio-option", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "radio",
                name: "format",
                value: "csv",
                checked: exportFormat === "csv",
                onChange: (e) => setExportFormat(e.target.value)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "format-label", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CSV" }),
              " - Dados tabulares para análise"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "radio-option", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "radio",
                name: "format",
                value: "xml",
                checked: exportFormat === "xml",
                onChange: (e) => setExportFormat(e.target.value)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "format-label", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "XML" }),
              " - Dados estruturados para sistemas"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "radio-option", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "radio",
                name: "format",
                value: "html",
                checked: exportFormat === "html",
                onChange: (e) => setExportFormat(e.target.value)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "format-label", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "HTML" }),
              " - Relatório formatado para leitura"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "radio-option", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "radio",
                name: "format",
                value: "bibtex",
                checked: exportFormat === "bibtex",
                onChange: (e) => setExportFormat(e.target.value)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "format-label", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "BibTeX" }),
              " - Referências bibliográficas para LaTeX"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "radio-option", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "radio",
                name: "format",
                value: "png",
                checked: exportFormat === "png",
                disabled: !isMapExportSupported(),
                onChange: (e) => setExportFormat(e.target.value)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "format-label", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "PNG" }),
              " - Imagem do mapa atual",
              !isMapExportSupported() && /* @__PURE__ */ jsxRuntimeExports.jsx("em", { children: " (não suportado neste navegador)" })
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Opções de Exportação" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-option", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: includeMetadata,
              onChange: (e) => setIncludeMetadata(e.target.checked)
            }
          ),
          "Incluir metadados (fonte, citação, URL)"
        ] }),
        exportFormat !== "png" && /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-option", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: includeMap,
              onChange: (e) => setIncludeMap(e.target.checked)
            }
          ),
          "Incluir informações geográficas"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Filtro de Data (Opcional)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "date-range", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "date-input-group", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { children: "Data inicial:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: dateRange.from,
                onChange: (e) => setDateRange(__spreadProps(__spreadValues({}, dateRange), { from: e.target.value })),
                "aria-label": "Data inicial"
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "date-input-group", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { children: "Data final:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: dateRange.to,
                onChange: (e) => setDateRange(__spreadProps(__spreadValues({}, dateRange), { to: e.target.value })),
                "aria-label": "Data final"
              }
            )
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-section citation-info", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Informações para Citação Acadêmica" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "citation-note", children: "Os dados exportados incluem informações completas de citação para uso acadêmico. Recomenda-se sempre verificar a fonte original dos documentos." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "suggested-citation", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Citação sugerida para esta pesquisa:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "citation-text", children: [
            "Mapa Legislativo Acadêmico. Dados legislativos georeferenciados do Brasil. Exportado em ",
            (/* @__PURE__ */ new Date()).toLocaleDateString("pt-BR"),
            ". Disponível em: [URL da aplicação]."
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "export-actions", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "cancel-btn", onClick: onClose, children: "Cancelar" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          className: "export-confirm-btn",
          onClick: handleExport,
          disabled: documents.length === 0 || exportStatus === "generating",
          children: [
            exportStatus === "checking" && "🔍 Verificando cache...",
            exportStatus === "generating" && "⏳ Gerando exportação...",
            exportStatus === "ready" && "✅ Pronto!",
            exportStatus === "idle" && `Exportar ${exportFormat === "png" ? "Imagem PNG" : exportFormat.toUpperCase()}`
          ]
        }
      )
    ] })
  ] }) });
};
var ExportPanel_default = ExportPanel;
export {
  ExportPanel_default as default
};
