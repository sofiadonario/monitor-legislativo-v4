const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/OptimizedMap-DqW0E1q-.js","assets/js/index-B7i3lUh2.js","assets/js/react-vendor-D_QSeeZk.js","assets/js/leaflet-vendor-HKOewaEh.js","assets/css/index-CuWVk-Hd.css","assets/css/OptimizedMap-Dlna1-ep.css","assets/js/TabbedSidebar-Bwtbm432.js","assets/css/TabbedSidebar-Abd64lRR.css","assets/js/ExportPanel-BzR39aOH.js","assets/js/utils-C418i17z.js","assets/css/ExportPanel-rPKiQ0eQ.css"])))=>i.map(i=>d[i]);
var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { j as jsxRuntimeExports, L as LoadingSpinner, _ as __vitePreload } from "./index-B7i3lUh2.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
import "./react-vendor-D_QSeeZk.js";
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
  const lines = csvContent.split("\\n").filter((line) => line.trim() !== "");
  if (lines.length < 2) {
    console.warn("CSV content has no data rows.");
    return [];
  }
  const headers = parseCSVLine(lines[0]).map((h) => h.trim().replace(/['"]+/g, ""));
  console.log("CSV Headers:", headers);
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
async function loadCSVLegislativeData() {
  const CSV_URL = "/lexml_transport_results_20250606_123100.csv";
  console.log(`Fetching CSV data from: ${CSV_URL}`);
  try {
    const response = await fetch(CSV_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch CSV: ${response.status} ${response.statusText}`);
    }
    const csvContent = await response.text();
    if (!csvContent) {
      throw new Error("CSV file is empty or could not be read.");
    }
    return parseCSVData(csvContent);
  } catch (error) {
    console.error("Error loading or parsing CSV legislative data:", error);
    throw error;
  }
}
let csvDataCache = null;
const csvLegislativeData = [];
(async () => {
  try {
    console.log("🔥 FORCE LOADING FULL CSV DATASET (889 rows)...");
    csvDataCache = await loadCSVLegislativeData();
    if (csvDataCache && csvDataCache.length > 0) {
      csvLegislativeData.length = 0;
      csvLegislativeData.push(...csvDataCache);
      console.log(`✅ SUCCESS: Loaded ${csvDataCache.length} documents from CSV`);
    } else {
      console.error("❌ CSV loading failed - no data returned");
    }
  } catch (error) {
    console.error("❌ CRITICAL: Failed to load CSV data on module import:", error);
  }
})();
class ApiClient {
  constructor(config) {
    __publicField(this, "config");
    __publicField(this, "cache", /* @__PURE__ */ new Map());
    this.config = {
      baseUrl: config.baseUrl,
      version: config.version,
      timeout: config.timeout ?? 3e4,
      retries: config.retries ?? 3,
      cacheEnabled: config.cacheEnabled ?? true,
      cacheTTL: config.cacheTTL ?? 3e5
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
  async fetchWithRetry(url, options, retries = this.config.retries) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
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
        await this.delay(1e3 * (this.config.retries - retries + 1));
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
          await this.delay(1e3 * (this.config.retries - retries + 1));
          return this.fetchWithRetry(url, options, retries - 1);
        }
      }
      throw new ApiError("Network error", 0);
    }
  }
  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async get(endpoint, params) {
    const cacheKey = this.getCacheKey(endpoint, params);
    const cached = this.getFromCache(cacheKey);
    if (cached !== null) {
      return cached;
    }
    const queryString = params ? `?${new URLSearchParams(params).toString()}` : "";
    const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}${queryString}`;
    const response = await this.fetchWithRetry(url, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      }
    });
    const data = await response.json();
    this.saveToCache(cacheKey, data);
    return data;
  }
  async post(endpoint, body) {
    const url = `${this.config.baseUrl}/api/${this.config.version}${endpoint}`;
    const response = await this.fetchWithRetry(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });
    return response.json();
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
new ApiClient({
  baseUrl: "https://monitor-legislativo-v4-production.up.railway.app",
  version: "v1",
  cacheEnabled: true,
  cacheTTL: Number(void 0) || 3e5
});
const _LegislativeDataService = class _LegislativeDataService {
  constructor() {
    __publicField(this, "csvDataCache", null);
  }
  static getInstance() {
    if (!_LegislativeDataService.instance) {
      _LegislativeDataService.instance = new _LegislativeDataService();
    }
    return _LegislativeDataService.instance;
  }
  async getLocalCsvData() {
    if (this.csvDataCache) {
      console.log("Using cached CSV data.");
      return { documents: this.csvDataCache, usingFallback: true };
    }
    try {
      console.log("Attempting to load CSV legislative data...");
      const csvDocs = await loadCSVLegislativeData();
      if (csvDocs.length > 0) {
        console.log(`Loaded ${csvDocs.length} documents from CSV`);
        this.csvDataCache = csvDocs;
        return { documents: csvDocs, usingFallback: true };
      }
      throw new Error("CSV file was loaded but contained no documents.");
    } catch (error) {
      console.error("Critical error: Failed to load or parse CSV data.", error);
      return { documents: [], usingFallback: true };
    }
  }
  async fetchDocuments(filters) {
    {
      console.log("Force CSV-only mode. Using local CSV file exclusively.");
      const localData = await this.getLocalCsvData();
      return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
    }
  }
  async fetchDocumentById(id) {
    const allDocs = await this.fetchDocuments();
    return allDocs.documents.find((doc) => doc.id === id) || null;
  }
  async searchDocuments(searchTerm) {
    const allDocs = await this.fetchDocuments();
    const lowerSearchTerm = searchTerm.toLowerCase();
    return allDocs.documents.filter(
      (doc) => doc.title.toLowerCase().includes(lowerSearchTerm) || doc.summary.toLowerCase().includes(lowerSearchTerm) || doc.keywords && doc.keywords.some((keyword) => keyword.toLowerCase().includes(lowerSearchTerm))
    );
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
    if (!filters) return {};
    const params = {};
    if (filters.searchTerm) params.search = filters.searchTerm;
    if (filters.documentTypes.length > 0) params.types = filters.documentTypes.join(",");
    if (filters.states.length > 0) params.states = filters.states.join(",");
    if (filters.municipalities.length > 0) params.municipalities = filters.municipalities.join(",");
    if (filters.chambers.length > 0) params.chambers = filters.chambers.join(",");
    if (filters.dateFrom) params.date_from = filters.dateFrom.toISOString();
    if (filters.dateTo) params.date_to = filters.dateTo.toISOString();
    if (filters.keywords.length > 0) params.keywords = filters.keywords.join(",");
    return params;
  }
  transformApiResponse(data) {
    return data.map((item) => this.transformApiDocument(item));
  }
  transformApiDocument(item) {
    return {
      id: item.id || item._id,
      title: item.title,
      summary: item.summary || item.description,
      type: item.type || item.document_type,
      date: new Date(item.date || item.created_at),
      keywords: item.keywords || item.tags || [],
      state: item.state || item.estado,
      municipality: item.municipality || item.municipio,
      url: item.url || item.link,
      status: item.status || "em_tramitacao",
      author: item.author || item.autor,
      chamber: item.chamber || item.camara
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
const OptimizedMap = reactExports.lazy(() => __vitePreload(() => import("./OptimizedMap-DqW0E1q-.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0).then((module) => ({ default: module.OptimizedMap })));
const TabbedSidebar = reactExports.lazy(() => __vitePreload(() => import("./TabbedSidebar-Bwtbm432.js"), true ? __vite__mapDeps([6,1,2,3,4,7]) : void 0).then((module) => ({ default: module.TabbedSidebar })));
const ExportPanel = reactExports.lazy(() => __vitePreload(() => import("./ExportPanel-BzR39aOH.js"), true ? __vite__mapDeps([8,1,2,3,4,9,10]) : void 0).then((module) => ({ default: module.ExportPanel })));
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
      return { ...state, sidebarOpen: !state.sidebarOpen };
    case "SET_SIDEBAR_OPEN":
      return { ...state, sidebarOpen: action.payload };
    case "TOGGLE_EXPORT_PANEL":
      return { ...state, exportPanelOpen: !state.exportPanelOpen };
    case "SELECT_STATE":
      return { ...state, selectedState: action.payload, selectedMunicipality: void 0 };
    case "SELECT_MUNICIPALITY":
      return { ...state, selectedMunicipality: action.payload };
    case "CLEAR_SELECTION":
      return { ...state, selectedState: void 0, selectedMunicipality: void 0 };
    case "UPDATE_FILTERS":
      return { ...state, filters: action.payload };
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
  useKeyboardNavigation();
  reactExports.useEffect(() => {
    const loadDocuments = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const { documents: docs, usingFallback } = await legislativeDataService.fetchDocuments(filters);
        if (docs.length === 0 && usingFallback) {
          setError("Could not load from API or CSV. Please check data sources.");
        }
        setDocuments(docs);
        setUsingFallbackData(usingFallback);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : "An unknown error occurred";
        setError(errorMessage);
        console.error("Error loading documents:", err);
      } finally {
        setIsLoading(false);
      }
    };
    loadDocuments();
  }, [filters]);
  const handleLocationClick = reactExports.useCallback((type, id) => {
    dispatch({ type: type === "state" ? "SELECT_STATE" : "SELECT_MUNICIPALITY", payload: id });
  }, []);
  const handleClearSelection = reactExports.useCallback(() => dispatch({ type: "CLEAR_SELECTION" }), []);
  const onFiltersChange = reactExports.useCallback((newFilters) => dispatch({ type: "UPDATE_FILTERS", payload: newFilters }), []);
  const toggleSidebar = reactExports.useCallback(() => dispatch({ type: "TOGGLE_SIDEBAR" }), []);
  const toggleExportPanel = reactExports.useCallback(() => dispatch({ type: "TOGGLE_EXPORT_PANEL" }), []);
  const filteredDocuments = reactExports.useMemo(() => {
    return documents.filter((doc) => {
      if (selectedState && doc.state !== selectedState) return false;
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) return false;
      return true;
    });
  }, [documents, selectedState, selectedMunicipality]);
  const highlightedStates = reactExports.useMemo(
    () => [...new Set(filteredDocuments.map((doc) => doc.state).filter(Boolean))],
    [filteredDocuments]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "dashboard", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading sidebar..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      TabbedSidebar,
      {
        isOpen: sidebarOpen,
        onToggle: toggleSidebar,
        filters,
        onFiltersChange,
        documents,
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
            documents: filteredDocuments,
            onLocationClick: handleLocationClick,
            highlightedLocations: highlightedStates
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
        documents: filteredDocuments
      }
    ) })
  ] });
};
export {
  Dashboard as default
};
