const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/OptimizedMap-CYqL_-QL.js","assets/js/index-m_XgFlqP.js","assets/js/react-vendor-D_QSeeZk.js","assets/js/leaflet-vendor-HKOewaEh.js","assets/css/index-CpfVDpBa.css","assets/css/OptimizedMap-Dlna1-ep.css","assets/js/TabbedSidebar-DQ6lAQOn.js","assets/css/TabbedSidebar-DBx0Wajg.css","assets/js/ExportPanel-Dfubbp77.js","assets/js/utils-C418i17z.js","assets/css/ExportPanel-rPKiQ0eQ.css","assets/js/BudgetRealtimeStatus-DoNW5h1x.js","assets/css/BudgetRealtimeStatus-CIH_vEBZ.css"])))=>i.map(i=>d[i]);
var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { j as jsxRuntimeExports, L as LoadingSpinner, _ as __vitePreload } from "./index-m_XgFlqP.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
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
const apiClient = new ApiClient({
  baseUrl: "https://monitor-legislativo-v4-production.up.railway.app",
  version: "v1",
  cacheEnabled: true,
  cacheTTL: Number(void 0) || 3e5
});
const _LegislativeDataService = class _LegislativeDataService {
  constructor() {
  }
  static getInstance() {
    if (!_LegislativeDataService.instance) {
      _LegislativeDataService.instance = new _LegislativeDataService();
    }
    return _LegislativeDataService.instance;
  }
  async fetchDocuments(filters) {
    try {
      const params = this.buildQueryParams(filters);
      const data = await apiClient.get("/documents", params);
      return this.transformApiResponse(data);
    } catch (error) {
      console.error("Failed to fetch from API, falling back to mock data:", error);
      throw error;
    }
  }
  async fetchDocumentById(id) {
    try {
      const data = await apiClient.get(`/documents/${id}`);
      return this.transformApiDocument(data);
    } catch (error) {
      if (error instanceof ApiError && error.statusCode === 404) {
        return null;
      }
      console.error("Failed to fetch document from API:", error);
      throw error;
    }
  }
  async searchDocuments(searchTerm) {
    try {
      const data = await apiClient.get("/documents/search", { q: searchTerm });
      return this.transformApiResponse(data);
    } catch (error) {
      console.error("Search API failed:", error);
      throw error;
    }
  }
  filterMockData(data, filters) {
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
const OptimizedMap = reactExports.lazy(() => __vitePreload(() => import("./OptimizedMap-CYqL_-QL.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0).then((module) => ({ default: module.OptimizedMap })));
const TabbedSidebar = reactExports.lazy(() => __vitePreload(() => import("./TabbedSidebar-DQ6lAQOn.js"), true ? __vite__mapDeps([6,1,2,3,4,7]) : void 0).then((module) => ({ default: module.TabbedSidebar })));
const ExportPanel = reactExports.lazy(() => __vitePreload(() => import("./ExportPanel-Dfubbp77.js"), true ? __vite__mapDeps([8,1,2,3,4,9,10]) : void 0).then((module) => ({ default: module.ExportPanel })));
const BudgetRealtimeStatus = reactExports.lazy(() => __vitePreload(() => import("./BudgetRealtimeStatus-DoNW5h1x.js"), true ? __vite__mapDeps([11,1,2,3,4,12]) : void 0).then((module) => ({ default: module.BudgetRealtimeStatus })));
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
    keywords: [],
    dateFrom: void 0,
    dateTo: void 0
  }
};
const dashboardReducer = (state, action) => {
  switch (action.type) {
    case "TOGGLE_SIDEBAR":
      return { ...state, sidebarOpen: !state.sidebarOpen };
    case "TOGGLE_EXPORT_PANEL":
      return { ...state, exportPanelOpen: !state.exportPanelOpen };
    case "SET_SIDEBAR_OPEN":
      return { ...state, sidebarOpen: action.payload };
    case "SELECT_STATE":
      return {
        ...state,
        selectedState: action.payload,
        selectedMunicipality: void 0
      };
    case "SELECT_MUNICIPALITY":
      return { ...state, selectedMunicipality: action.payload };
    case "CLEAR_SELECTION":
      return {
        ...state,
        selectedState: void 0,
        selectedMunicipality: void 0
      };
    case "UPDATE_FILTERS":
      return { ...state, filters: action.payload };
    case "CLOSE_EXPORT_PANEL":
      return { ...state, exportPanelOpen: false };
    default:
      return state;
  }
};
const Dashboard = () => {
  const [state, dispatch] = reactExports.useReducer(dashboardReducer, initialState);
  const [documents, setDocuments] = reactExports.useState([]);
  const [isLoading, setIsLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const { sidebarOpen, exportPanelOpen, selectedState, selectedMunicipality, filters } = state;
  const mainContentRef = reactExports.useRef(null);
  const skipLinkRef = reactExports.useRef(null);
  useKeyboardNavigation();
  reactExports.useEffect(() => {
    const loadDocuments = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const docs = await legislativeDataService.fetchDocuments(filters);
        setDocuments(docs);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load documents");
        console.error("Error loading documents:", err);
      } finally {
        setIsLoading(false);
      }
    };
    loadDocuments();
  }, [filters]);
  reactExports.useEffect(() => {
    const handleResize = () => {
      const shouldOpenSidebar = window.innerWidth >= 768;
      dispatch({ type: "SET_SIDEBAR_OPEN", payload: shouldOpenSidebar });
    };
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);
  const handleLocationClick = reactExports.useCallback((type, id) => {
    if (type === "state") {
      dispatch({ type: "SELECT_STATE", payload: id });
    } else {
      dispatch({ type: "SELECT_MUNICIPALITY", payload: id });
    }
    if (window.innerWidth < 768) {
      dispatch({ type: "SET_SIDEBAR_OPEN", payload: false });
    }
  }, []);
  const handleClearSelection = reactExports.useCallback(() => {
    dispatch({ type: "CLEAR_SELECTION" });
  }, []);
  reactExports.useCallback((options) => {
    console.log("Exporting with options:", options);
    dispatch({ type: "CLOSE_EXPORT_PANEL" });
  }, []);
  const toggleSidebar = reactExports.useCallback(() => {
    dispatch({ type: "TOGGLE_SIDEBAR" });
    const announcement = sidebarOpen ? "Sidebar closed" : "Sidebar opened";
    announceToScreenReader(announcement);
  }, [sidebarOpen]);
  const toggleExportPanel = reactExports.useCallback(() => {
    dispatch({ type: "TOGGLE_EXPORT_PANEL" });
    const announcement = exportPanelOpen ? "Export panel closed" : "Export panel opened";
    announceToScreenReader(announcement);
  }, [exportPanelOpen]);
  const announceToScreenReader = reactExports.useCallback((message) => {
    const announcement = document.createElement("div");
    announcement.setAttribute("aria-live", "polite");
    announcement.setAttribute("aria-atomic", "true");
    announcement.className = "sr-only";
    announcement.textContent = message;
    document.body.appendChild(announcement);
    setTimeout(() => document.body.removeChild(announcement), 1e3);
  }, []);
  const skipToMainContent = reactExports.useCallback((event) => {
    var _a;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      (_a = mainContentRef.current) == null ? void 0 : _a.focus();
    }
  }, []);
  const filteredDocuments = reactExports.useMemo(() => {
    return documents.filter((doc) => {
      if (filters.searchTerm && !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.keywords.some((keyword) => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
        return false;
      }
      if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
        return false;
      }
      if (filters.dateFrom) {
        const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
        if (docDate < filters.dateFrom) return false;
      }
      if (filters.dateTo) {
        const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
        if (docDate > filters.dateTo) return false;
      }
      if (selectedState && doc.state !== selectedState) {
        return false;
      }
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) {
        return false;
      }
      return true;
    });
  }, [documents, filters, selectedState, selectedMunicipality]);
  const highlightedStates = reactExports.useMemo(
    () => [...new Set(filteredDocuments.map((doc) => doc.state).filter(Boolean))],
    [filteredDocuments]
  );
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "dashboard-error", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Error Loading Data" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => window.location.reload(), children: "Retry" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "dashboard", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        ref: skipLinkRef,
        href: "#main-content",
        className: "skip-link sr-only",
        onKeyDown: skipToMainContent,
        onClick: (e) => {
          var _a;
          e.preventDefault();
          (_a = mainContentRef.current) == null ? void 0 : _a.focus();
        },
        children: "Skip to main content"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", id: "announcements" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading sidebar..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      TabbedSidebar,
      {
        isOpen: sidebarOpen,
        onToggle: toggleSidebar,
        filters,
        onFiltersChange: (newFilters) => dispatch({ type: "UPDATE_FILTERS", payload: newFilters }),
        documents,
        selectedState,
        onClearSelection: handleClearSelection
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "main",
      {
        id: "main-content",
        ref: mainContentRef,
        className: `main-content ${sidebarOpen ? "with-sidebar" : "full-width"}`,
        tabIndex: -1,
        role: "main",
        "aria-label": "Main content area",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "toolbar", role: "banner", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "toolbar-left", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "page-title", children: "Brazilian Transport Legislation Monitor" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "subtitle", id: "page-description", children: "Academic research platform for transport legislation analysis" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: null, children: /* @__PURE__ */ jsxRuntimeExports.jsx(BudgetRealtimeStatus, {}) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "toolbar-right", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "button",
                {
                  className: "export-btn",
                  onClick: toggleExportPanel,
                  "aria-label": `Export data ${exportPanelOpen ? "(panel currently open)" : ""}`,
                  "aria-expanded": exportPanelOpen,
                  "aria-controls": "export-panel",
                  type: "button",
                  children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "📊" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Exportar" })
                  ]
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stats", role: "status", "aria-live": "polite", children: isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-item", children: "Loading..." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-item", "aria-label": `${filteredDocuments.length} documents found`, children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "📄" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                    filteredDocuments.length,
                    " documentos"
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "stat-item", "aria-label": `${highlightedStates.length} states with documents`, children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "🗺️" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                    highlightedStates.length,
                    " estados"
                  ] })
                ] })
              ] }) })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "section",
            {
              className: "map-wrapper",
              "aria-labelledby": "map-heading",
              role: "region",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "map-heading", className: "sr-only", children: "Interactive map of Brazilian states with legislative documents" }),
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
              ]
            }
          ),
          (selectedState || selectedMunicipality) && /* @__PURE__ */ jsxRuntimeExports.jsx(
            "aside",
            {
              className: "info-panel",
              role: "complementary",
              "aria-labelledby": "location-info-heading",
              "aria-live": "polite",
              children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "info-content", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: "location-info-heading", children: [
                  selectedState && !selectedMunicipality && `Estado: ${selectedState}`,
                  selectedMunicipality && `Município: ${selectedMunicipality}, ${selectedState}`
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                  filteredDocuments.length,
                  " documentos encontrados nesta localização"
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs(
                  "button",
                  {
                    onClick: handleClearSelection,
                    className: "close-info",
                    "aria-label": "Clear location selection",
                    type: "button",
                    children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "✕" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Fechar" })
                    ]
                  }
                )
              ] })
            }
          )
        ]
      }
    ),
    exportPanelOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading export panel..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExportPanel,
      {
        isOpen: exportPanelOpen,
        onClose: toggleExportPanel,
        documents: filteredDocuments
      }
    ) })
  ] });
};
const Dashboard$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: Dashboard
}, Symbol.toStringTag, { value: "Module" }));
export {
  Dashboard$1 as D,
  legislativeDataService as l
};
