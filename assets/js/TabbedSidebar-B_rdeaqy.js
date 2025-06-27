import { j as jsxRuntimeExports } from "./index-CREcncgK.js";
import { r as reactExports, R as React } from "./leaflet-vendor-BcXhkSxI.js";
import "./react-vendor-CSPBeBBz.js";
const DataVisualization = ({ documents }) => {
  const stats = reactExports.useMemo(() => {
    const now = /* @__PURE__ */ new Date();
    const sixMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 6, 1);
    const oneYearAgo = new Date(now.getFullYear() - 1, now.getMonth(), 1);
    const typeCount = /* @__PURE__ */ new Map();
    const stateCount = /* @__PURE__ */ new Map();
    const monthlyCount = /* @__PURE__ */ new Map();
    const keywordCount = /* @__PURE__ */ new Map();
    documents.forEach((doc) => {
      typeCount.set(doc.type, (typeCount.get(doc.type) || 0) + 1);
      if (doc.state) {
        stateCount.set(doc.state, (stateCount.get(doc.state) || 0) + 1);
      }
      const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
      const monthKey = `${docDate.getFullYear()}-${String(docDate.getMonth() + 1).padStart(2, "0")}`;
      monthlyCount.set(monthKey, (monthlyCount.get(monthKey) || 0) + 1);
      doc.keywords.forEach((keyword) => {
        keywordCount.set(keyword, (keywordCount.get(keyword) || 0) + 1);
      });
    });
    const total = documents.length;
    const typeData = Array.from(typeCount.entries()).map(([label, value]) => ({
      label,
      value,
      percentage: value / total * 100
    })).sort((a, b) => b.value - a.value);
    const stateData = Array.from(stateCount.entries()).map(([label, value]) => ({
      label,
      value,
      percentage: value / total * 100
    })).sort((a, b) => b.value - a.value).slice(0, 10);
    const keywordData = Array.from(keywordCount.entries()).map(([label, value]) => ({
      label,
      value,
      percentage: value / total * 100
    })).sort((a, b) => b.value - a.value).slice(0, 15);
    const monthlyData = [];
    for (let i = 11; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      const count = monthlyCount.get(monthKey) || 0;
      monthlyData.push({
        label: date.toLocaleDateString("pt-BR", { month: "short", year: "2-digit" }),
        value: count,
        percentage: 0
      });
    }
    const recentDocs = documents.filter((doc) => {
      const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
      return docDate >= sixMonthsAgo;
    }).length;
    const yearlyDocs = documents.filter((doc) => {
      const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
      return docDate >= oneYearAgo;
    }).length;
    return {
      total,
      recentDocs,
      yearlyDocs,
      typeData,
      stateData,
      keywordData,
      monthlyData,
      averagePerMonth: Math.round(yearlyDocs / 12)
    };
  }, [documents]);
  const BarChart = ({ data, maxValue }) => {
    const max = maxValue || Math.max(...data.map((d) => d.value));
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bar-chart", children: data.map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bar-item", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bar-label", children: item.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bar-container", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "bar-fill",
          style: { width: `${item.value / max * 100}%` },
          children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "bar-value", children: item.value })
        }
      ) }),
      item.percentage > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bar-percentage", children: [
        item.percentage.toFixed(1),
        "%"
      ] })
    ] }, index)) });
  };
  const LineChart = ({ data }) => {
    const maxValue = Math.max(...data.map((d) => d.value));
    const height = 200;
    const width = 100;
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "line-chart", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("svg", { viewBox: `0 0 ${width * data.length} ${height + 40}`, preserveAspectRatio: "none", children: [
      [0, 25, 50, 75, 100].map((percent) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "line",
        {
          x1: "0",
          y1: height - height * percent / 100,
          x2: width * data.length,
          y2: height - height * percent / 100,
          stroke: "#e0e0e0",
          strokeWidth: "1"
        },
        percent
      )),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "polyline",
        {
          points: data.map(
            (item, index) => `${index * width + width / 2},${height - item.value / maxValue * height}`
          ).join(" "),
          fill: "none",
          stroke: "#1976d2",
          strokeWidth: "2"
        }
      ),
      data.map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("g", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "circle",
          {
            cx: index * width + width / 2,
            cy: height - item.value / maxValue * height,
            r: "4",
            fill: "#1976d2"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "text",
          {
            x: index * width + width / 2,
            y: height + 20,
            textAnchor: "middle",
            fontSize: "12",
            fill: "#666",
            children: item.label
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "text",
          {
            x: index * width + width / 2,
            y: height - item.value / maxValue * height - 10,
            textAnchor: "middle",
            fontSize: "11",
            fill: "#333",
            fontWeight: "bold",
            children: item.value
          }
        )
      ] }, index))
    ] }) });
  };
  const KeywordCloud = ({ data }) => {
    const maxCount = Math.max(...data.map((d) => d.value));
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "keyword-cloud", children: data.map((item, index) => {
      const size = 0.8 + item.value / maxCount * 1.2;
      const opacity = 0.6 + item.value / maxCount * 0.4;
      return /* @__PURE__ */ jsxRuntimeExports.jsx(
        "span",
        {
          className: "keyword-tag",
          style: {
            fontSize: `${size}rem`,
            opacity,
            color: `hsl(${200 + index * 10}, 70%, 45%)`
          },
          title: `${item.value} documents`,
          children: item.label
        },
        index
      );
    }) });
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "data-visualization", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Legislative Analytics Dashboard" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stats-grid", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-card", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-icon", children: "📊" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-content", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-value", children: stats.total }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-label", children: "Total Documents" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-card", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-icon", children: "📅" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-content", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-value", children: stats.recentDocs }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-label", children: "Last 6 Months" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-card", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-icon", children: "📈" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-content", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-value", children: stats.averagePerMonth }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-label", children: "Avg. per Month" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-card", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-icon", children: "🗓️" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-content", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-value", children: stats.yearlyDocs }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-label", children: "This Year" })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "charts-grid", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "chart-container", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Document Types Distribution" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(BarChart, { data: stats.typeData })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "chart-container", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Top States by Legislation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(BarChart, { data: stats.stateData })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "chart-container full-width", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Monthly Trend (Last 12 Months)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LineChart, { data: stats.monthlyData })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "chart-container full-width", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Popular Keywords" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(KeywordCloud, { data: stats.keywordData })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "visualization-actions", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        className: "export-chart-btn",
        onClick: () => {
          const csv = [
            ["Metric", "Value"],
            ["Total Documents", stats.total],
            ["Recent Documents (6 months)", stats.recentDocs],
            ["Yearly Documents", stats.yearlyDocs],
            ["Average per Month", stats.averagePerMonth],
            "",
            ["Document Type", "Count", "Percentage"],
            ...stats.typeData.map((d) => [d.label, d.value, d.percentage.toFixed(1) + "%"]),
            "",
            ["State", "Count", "Percentage"],
            ...stats.stateData.map((d) => [d.label, d.value, d.percentage.toFixed(1) + "%"])
          ].map((row) => row.join(",")).join("\n");
          const blob = new Blob([csv], { type: "text/csv" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `legislative-analytics-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.csv`;
          a.click();
          URL.revokeObjectURL(url);
        },
        children: "📥 Export Analytics (CSV)"
      }
    ) })
  ] });
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
var __publicField = (obj, key, value) => __defNormalProp$1(obj, typeof key !== "symbol" ? key + "" : key, value);
const STORAGE_KEY = "monitor_legislativo_saved_queries";
const _SavedQueriesService = class _SavedQueriesService2 {
  constructor() {
    __publicField(this, "queries", []);
    this.loadQueries();
  }
  static getInstance() {
    if (!_SavedQueriesService2.instance) {
      _SavedQueriesService2.instance = new _SavedQueriesService2();
    }
    return _SavedQueriesService2.instance;
  }
  loadQueries() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        this.queries = JSON.parse(stored);
      }
    } catch (error) {
      console.error("Error loading saved queries:", error);
      this.queries = [];
    }
  }
  saveQueries() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.queries));
    } catch (error) {
      console.error("Error saving queries:", error);
    }
  }
  generateId() {
    return `query_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  getAllQueries() {
    return [...this.queries].sort(
      (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );
  }
  getPublicQueries() {
    return this.queries.filter((q) => q.isPublic);
  }
  getRecentQueries(limit = 5) {
    return this.getAllQueries().slice(0, limit);
  }
  getPopularQueries(limit = 5) {
    return [...this.queries].sort((a, b) => b.timesUsed - a.timesUsed).slice(0, limit);
  }
  getQueryById(id) {
    return this.queries.find((q) => q.id === id);
  }
  saveQuery(name, filters, options = {}) {
    var _a;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const query = {
      id: this.generateId(),
      name: name.trim(),
      description: (_a = options.description) == null ? void 0 : _a.trim(),
      filters: __spreadValues$1({}, filters),
      createdAt: now,
      updatedAt: now,
      timesUsed: 0,
      isPublic: options.isPublic || false,
      tags: options.tags || []
    };
    this.queries.push(query);
    this.saveQueries();
    return query;
  }
  updateQuery(id, updates) {
    const index = this.queries.findIndex((q) => q.id === id);
    if (index === -1) return null;
    const query = this.queries[index];
    this.queries[index] = __spreadProps$1(__spreadValues$1(__spreadValues$1({}, query), updates), {
      updatedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
    this.saveQueries();
    return this.queries[index];
  }
  deleteQuery(id) {
    const index = this.queries.findIndex((q) => q.id === id);
    if (index === -1) return false;
    this.queries.splice(index, 1);
    this.saveQueries();
    return true;
  }
  useQuery(id) {
    const query = this.getQueryById(id);
    if (!query) return null;
    query.timesUsed++;
    query.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.saveQueries();
    return query;
  }
  duplicateQuery(id, newName) {
    const original = this.getQueryById(id);
    if (!original) return null;
    return this.saveQuery(newName, original.filters, {
      description: original.description,
      isPublic: false,
      // Duplicates are private by default
      tags: [...original.tags]
    });
  }
  searchQueries(searchTerm) {
    const term = searchTerm.toLowerCase();
    return this.queries.filter(
      (query) => {
        var _a;
        return query.name.toLowerCase().includes(term) || ((_a = query.description) == null ? void 0 : _a.toLowerCase().includes(term)) || query.tags.some((tag) => tag.toLowerCase().includes(term)) || query.filters.searchTerm.toLowerCase().includes(term);
      }
    );
  }
  getQueriesByTag(tag) {
    return this.queries.filter(
      (query) => query.tags.some((t) => t.toLowerCase() === tag.toLowerCase())
    );
  }
  getAllTags() {
    const tags = /* @__PURE__ */ new Set();
    this.queries.forEach((query) => {
      query.tags.forEach((tag) => tags.add(tag));
    });
    return Array.from(tags).sort();
  }
  exportQueries() {
    return JSON.stringify(this.queries, null, 2);
  }
  importQueries(jsonData) {
    try {
      const imported = JSON.parse(jsonData);
      if (!Array.isArray(imported)) {
        return { success: false, imported: 0, errors: ["Invalid format: expected array"] };
      }
      const errors = [];
      let importedCount = 0;
      imported.forEach((item, index) => {
        try {
          if (!this.isValidQuery(item)) {
            errors.push(`Query ${index + 1}: Invalid format`);
            return;
          }
          const existing = this.queries.find((q) => q.name === item.name);
          if (existing) {
            errors.push(`Query "${item.name}": Name already exists`);
            return;
          }
          const query = __spreadProps$1(__spreadValues$1({}, item), {
            id: this.generateId(),
            createdAt: (/* @__PURE__ */ new Date()).toISOString(),
            updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
            timesUsed: 0
          });
          this.queries.push(query);
          importedCount++;
        } catch (error) {
          errors.push(`Query ${index + 1}: ${error instanceof Error ? error.message : "Unknown error"}`);
        }
      });
      if (importedCount > 0) {
        this.saveQueries();
      }
      return {
        success: importedCount > 0,
        imported: importedCount,
        errors
      };
    } catch (error) {
      return {
        success: false,
        imported: 0,
        errors: [`Parse error: ${error instanceof Error ? error.message : "Unknown error"}`]
      };
    }
  }
  isValidQuery(item) {
    return typeof item === "object" && item !== null && typeof item.name === "string" && item.name.trim().length > 0 && typeof item.filters === "object" && item.filters !== null && typeof item.filters.searchTerm === "string" && Array.isArray(item.filters.documentTypes) && Array.isArray(item.filters.states) && Array.isArray(item.filters.keywords) && typeof item.isPublic === "boolean" && Array.isArray(item.tags);
  }
  clearAllQueries() {
    this.queries = [];
    this.saveQueries();
  }
  getStats() {
    const total = this.queries.length;
    const publicQueries = this.queries.filter((q) => q.isPublic).length;
    const totalUsage = this.queries.reduce((sum, q) => sum + q.timesUsed, 0);
    const mostUsed = this.queries.length > 0 ? this.queries.reduce((max, q) => q.timesUsed > max.timesUsed ? q : max) : null;
    return {
      total,
      public: publicQueries,
      private: total - publicQueries,
      mostUsed,
      totalUsage
    };
  }
};
__publicField(_SavedQueriesService, "instance");
let SavedQueriesService = _SavedQueriesService;
const savedQueriesService = SavedQueriesService.getInstance();
const SaveQueryModal = ({ isOpen, onClose, onSave, filters }) => {
  const [name, setName] = reactExports.useState("");
  const [description, setDescription] = reactExports.useState("");
  const [isPublic, setIsPublic] = reactExports.useState(false);
  const [tagsInput, setTagsInput] = reactExports.useState("");
  const [error, setError] = reactExports.useState("");
  const handleSave = () => {
    if (!name.trim()) {
      setError("Nome é obrigatório");
      return;
    }
    const tags = tagsInput.split(",").map((tag) => tag.trim()).filter((tag) => tag.length > 0);
    onSave(name.trim(), description.trim(), isPublic, tags);
    setName("");
    setDescription("");
    setIsPublic(false);
    setTagsInput("");
    setError("");
  };
  if (!isOpen) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "modal-overlay", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "modal-content", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "modal-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Salvar Consulta" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "modal-close", onClick: onClose, children: "×" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "modal-body", children: [
      error && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "error-message", children: error }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "form-group", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "query-name", children: "Nome da Consulta *" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            id: "query-name",
            type: "text",
            value: name,
            onChange: (e) => setName(e.target.value),
            placeholder: "Ex: Documentos sobre transporte público",
            maxLength: 100
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "form-group", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "query-description", children: "Descrição" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "textarea",
          {
            id: "query-description",
            value: description,
            onChange: (e) => setDescription(e.target.value),
            placeholder: "Descrição opcional da consulta",
            rows: 3,
            maxLength: 500
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "form-group", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "query-tags", children: "Tags (separadas por vírgula)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            id: "query-tags",
            type: "text",
            value: tagsInput,
            onChange: (e) => setTagsInput(e.target.value),
            placeholder: "Ex: transporte, infraestrutura, mobilidade"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "form-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-label", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "checkbox",
            checked: isPublic,
            onChange: (e) => setIsPublic(e.target.checked)
          }
        ),
        "Tornar consulta pública"
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-preview", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Preview da Consulta:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "preview-content", children: [
          filters.searchTerm && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            'Busca: "',
            filters.searchTerm,
            '"'
          ] }),
          filters.documentTypes.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            "Tipos: ",
            filters.documentTypes.join(", ")
          ] }),
          filters.states.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            "Estados: ",
            filters.states.join(", ")
          ] }),
          filters.keywords.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            "Palavras-chave: ",
            filters.keywords.join(", ")
          ] }),
          filters.dateFrom && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            "De: ",
            filters.dateFrom.toLocaleDateString()
          ] }),
          filters.dateTo && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "preview-tag", children: [
            "Até: ",
            filters.dateTo.toLocaleDateString()
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "modal-footer", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "btn-secondary", onClick: onClose, children: "Cancelar" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "btn-primary", onClick: handleSave, children: "Salvar Consulta" })
    ] })
  ] }) });
};
const SavedQueriesPanel = ({
  isOpen,
  onClose,
  onLoadQuery,
  currentFilters
}) => {
  const [queries, setQueries] = reactExports.useState([]);
  const [searchTerm, setSearchTerm] = reactExports.useState("");
  const [selectedTag, setSelectedTag] = reactExports.useState("");
  const [showSaveModal, setShowSaveModal] = reactExports.useState(false);
  const [activeTab, setActiveTab] = reactExports.useState("all");
  const [sortBy, setSortBy] = reactExports.useState("date");
  reactExports.useEffect(() => {
    loadQueries();
  }, []);
  const loadQueries = () => {
    setQueries(savedQueriesService.getAllQueries());
  };
  const filteredQueries = React.useMemo(() => {
    let filtered = queries;
    switch (activeTab) {
      case "recent":
        filtered = savedQueriesService.getRecentQueries();
        break;
      case "popular":
        filtered = savedQueriesService.getPopularQueries();
        break;
      case "public":
        filtered = savedQueriesService.getPublicQueries();
        break;
      default:
        filtered = queries;
    }
    if (searchTerm) {
      filtered = savedQueriesService.searchQueries(searchTerm);
    }
    if (selectedTag) {
      filtered = filtered.filter((q) => q.tags.includes(selectedTag));
    }
    switch (sortBy) {
      case "name":
        filtered.sort((a, b) => a.name.localeCompare(b.name));
        break;
      case "usage":
        filtered.sort((a, b) => b.timesUsed - a.timesUsed);
        break;
      case "date":
      default:
        filtered.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
    }
    return filtered;
  }, [queries, searchTerm, selectedTag, activeTab, sortBy]);
  const handleSaveQuery = (name, description, isPublic, tags) => {
    try {
      savedQueriesService.saveQuery(name, currentFilters, {
        description,
        isPublic,
        tags
      });
      loadQueries();
      setShowSaveModal(false);
    } catch (error) {
      console.error("Error saving query:", error);
    }
  };
  const handleLoadQuery = (query) => {
    savedQueriesService.useQuery(query.id);
    onLoadQuery(query.filters);
    loadQueries();
  };
  const handleDeleteQuery = (id) => {
    if (confirm("Tem certeza que deseja excluir esta consulta?")) {
      savedQueriesService.deleteQuery(id);
      loadQueries();
    }
  };
  const handleDuplicateQuery = (query) => {
    const newName = `${query.name} (cópia)`;
    savedQueriesService.duplicateQuery(query.id, newName);
    loadQueries();
  };
  const formatFilters = (filters) => {
    const parts = [];
    if (filters.searchTerm) parts.push(`"${filters.searchTerm}"`);
    if (filters.documentTypes.length > 0) parts.push(`Tipos: ${filters.documentTypes.length}`);
    if (filters.states.length > 0) parts.push(`Estados: ${filters.states.length}`);
    if (filters.keywords.length > 0) parts.push(`Tags: ${filters.keywords.length}`);
    return parts.join(" • ");
  };
  const allTags = savedQueriesService.getAllTags();
  const stats = savedQueriesService.getStats();
  if (!isOpen) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "saved-queries-overlay", onClick: onClose, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "saved-queries-panel", onClick: (e) => e.stopPropagation(), children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "panel-header", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Consultas Salvas" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "header-actions", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              className: "btn-primary btn-small",
              onClick: () => setShowSaveModal(true),
              disabled: !currentFilters.searchTerm && currentFilters.documentTypes.length === 0,
              children: "💾 Salvar Atual"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "panel-close", onClick: onClose, children: "×" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "panel-content", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stats-bar", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            stats.total,
            " consultas"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "•" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            stats.totalUsage,
            " usos"
          ] }),
          stats.mostUsed && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "•" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              'Mais usada: "',
              stats.mostUsed.name,
              '" (',
              stats.mostUsed.timesUsed,
              "x)"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-controls", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "text",
              placeholder: "Buscar consultas...",
              value: searchTerm,
              onChange: (e) => setSearchTerm(e.target.value),
              className: "search-input"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: selectedTag,
              onChange: (e) => setSelectedTag(e.target.value),
              className: "tag-filter",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Todas as tags" }),
                allTags.map((tag) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: tag, children: tag }, tag))
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: sortBy,
              onChange: (e) => setSortBy(e.target.value),
              className: "sort-select",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "date", children: "Por data" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "name", children: "Por nome" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "usage", children: "Por uso" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "tabs", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              className: `tab ${activeTab === "all" ? "active" : ""}`,
              onClick: () => setActiveTab("all"),
              children: [
                "Todas (",
                stats.total,
                ")"
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              className: `tab ${activeTab === "recent" ? "active" : ""}`,
              onClick: () => setActiveTab("recent"),
              children: "Recentes"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              className: `tab ${activeTab === "popular" ? "active" : ""}`,
              onClick: () => setActiveTab("popular"),
              children: "Populares"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              className: `tab ${activeTab === "public" ? "active" : ""}`,
              onClick: () => setActiveTab("public"),
              children: [
                "Públicas (",
                stats.public,
                ")"
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "queries-list", children: filteredQueries.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Nenhuma consulta encontrada." }),
          activeTab === "all" && !searchTerm && /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              className: "btn-primary",
              onClick: () => setShowSaveModal(true),
              disabled: !currentFilters.searchTerm && currentFilters.documentTypes.length === 0,
              children: "Salvar primeira consulta"
            }
          )
        ] }) : filteredQueries.map((query) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-main", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-header", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "query-name", children: query.name }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-meta", children: [
                query.isPublic && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "public-badge", children: "Público" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "usage-count", children: [
                  query.timesUsed,
                  " usos"
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "query-date", children: new Date(query.updatedAt).toLocaleDateString() })
              ] })
            ] }),
            query.description && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "query-description", children: query.description }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "query-filters", children: formatFilters(query.filters) }),
            query.tags.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "query-tags", children: query.tags.map((tag) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "tag", children: tag }, tag)) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "query-actions", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: "btn-primary btn-small",
                onClick: () => handleLoadQuery(query),
                children: "Usar"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: "btn-secondary btn-small",
                onClick: () => handleDuplicateQuery(query),
                children: "Duplicar"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: "btn-danger btn-small",
                onClick: () => handleDeleteQuery(query.id),
                children: "Excluir"
              }
            )
          ] })
        ] }, query.id)) })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SaveQueryModal,
      {
        isOpen: showSaveModal,
        onClose: () => setShowSaveModal(false),
        onSave: handleSaveQuery,
        filters: currentFilters
      }
    )
  ] });
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
const BRAZILIAN_STATES = [
  "AC",
  "AL",
  "AP",
  "AM",
  "BA",
  "CE",
  "DF",
  "ES",
  "GO",
  "MA",
  "MT",
  "MS",
  "MG",
  "PA",
  "PB",
  "PR",
  "PE",
  "PI",
  "RJ",
  "RN",
  "RS",
  "RO",
  "RR",
  "SC",
  "SP",
  "SE",
  "TO"
];
const EnhancedSearch = ({
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const [showSuggestions, setShowSuggestions] = reactExports.useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = reactExports.useState(-1);
  const [searchHistory, setSearchHistory] = reactExports.useState([]);
  const [showAdvanced, setShowAdvanced] = reactExports.useState(false);
  const [pendingFilters, setPendingFilters] = reactExports.useState(filters);
  const [showSavedQueries, setShowSavedQueries] = reactExports.useState(false);
  const searchInputRef = reactExports.useRef(null);
  const suggestionsRef = reactExports.useRef(null);
  const filterDebounceRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    setPendingFilters(filters);
  }, [filters]);
  const debouncedFilterUpdate = reactExports.useCallback((newFilters) => {
    if (filterDebounceRef.current) {
      clearTimeout(filterDebounceRef.current);
    }
    filterDebounceRef.current = setTimeout(() => {
      console.log("🎯 Filter batch: Applying batched filter changes", {
        searchTerm: newFilters.searchTerm,
        filtersCount: Object.keys(newFilters).filter((key) => {
          const value = newFilters[key];
          return Array.isArray(value) ? value.length > 0 : !!value;
        }).length
      });
      onFiltersChange(newFilters);
    }, 300);
  }, [onFiltersChange]);
  const handleFilterChange = reactExports.useCallback((updates) => {
    const newFilters = __spreadValues(__spreadValues({}, pendingFilters), updates);
    setPendingFilters(newFilters);
    debouncedFilterUpdate(newFilters);
  }, [pendingFilters, debouncedFilterUpdate]);
  reactExports.useEffect(() => {
    const history = localStorage.getItem("searchHistory");
    if (history) {
      setSearchHistory(JSON.parse(history));
    }
  }, []);
  reactExports.useEffect(() => {
    return () => {
      if (filterDebounceRef.current) {
        clearTimeout(filterDebounceRef.current);
      }
    };
  }, []);
  const facets = reactExports.useMemo(() => {
    const typeCounts = /* @__PURE__ */ new Map();
    const stateCounts = /* @__PURE__ */ new Map();
    const chamberCounts = /* @__PURE__ */ new Map();
    const keywordCounts = /* @__PURE__ */ new Map();
    documents.forEach((doc) => {
      typeCounts.set(doc.type, (typeCounts.get(doc.type) || 0) + 1);
      if (doc.state) stateCounts.set(doc.state, (stateCounts.get(doc.state) || 0) + 1);
      if (doc.chamber) chamberCounts.set(doc.chamber, (chamberCounts.get(doc.chamber) || 0) + 1);
      doc.keywords.forEach((keyword) => {
        keywordCounts.set(keyword, (keywordCounts.get(keyword) || 0) + 1);
      });
    });
    return { typeCounts, stateCounts, chamberCounts, keywordCounts };
  }, [documents]);
  const suggestions = reactExports.useMemo(() => {
    if (!pendingFilters.searchTerm || pendingFilters.searchTerm.length < 2) return [];
    const term = pendingFilters.searchTerm.toLowerCase();
    const results = [];
    Array.from(facets.keywordCounts.entries()).filter(([keyword]) => keyword.toLowerCase().includes(term)).sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([keyword, count]) => {
      results.push({ text: keyword, type: "keyword", count });
    });
    documents.filter((doc) => doc.title.toLowerCase().includes(term)).slice(0, 3).forEach((doc) => {
      results.push({ text: doc.title, type: "title" });
    });
    searchHistory.filter((search) => search.toLowerCase().includes(term) && search !== pendingFilters.searchTerm).slice(0, 2).forEach((search) => {
      results.push({ text: search, type: "recent" });
    });
    return results;
  }, [pendingFilters.searchTerm, facets, documents, searchHistory]);
  const handleSearchChange = (e) => {
    const value = e.target.value;
    handleFilterChange({ searchTerm: value });
    setShowSuggestions(true);
    setSelectedSuggestionIndex(-1);
  };
  const handleSearchSubmit = (searchTerm) => {
    const term = searchTerm || filters.searchTerm;
    if (term.trim()) {
      const newHistory = [term, ...searchHistory.filter((h) => h !== term)].slice(0, 10);
      setSearchHistory(newHistory);
      localStorage.setItem("searchHistory", JSON.stringify(newHistory));
    }
    setShowSuggestions(false);
  };
  const selectSuggestion = (suggestion) => {
    handleFilterChange({ searchTerm: suggestion.text });
    handleSearchSubmit(suggestion.text);
  };
  const handleKeyDown = (e) => {
    if (!showSuggestions || suggestions.length === 0) return;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setSelectedSuggestionIndex(
          (prev) => prev < suggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case "ArrowUp":
        e.preventDefault();
        setSelectedSuggestionIndex(
          (prev) => prev > 0 ? prev - 1 : suggestions.length - 1
        );
        break;
      case "Enter":
        e.preventDefault();
        if (selectedSuggestionIndex >= 0) {
          selectSuggestion(suggestions[selectedSuggestionIndex]);
        } else {
          handleSearchSubmit();
        }
        break;
      case "Escape":
        setShowSuggestions(false);
        setSelectedSuggestionIndex(-1);
        break;
    }
  };
  const handleDocumentTypeChange = (type) => {
    const newTypes = pendingFilters.documentTypes.includes(type) ? pendingFilters.documentTypes.filter((t) => t !== type) : [...pendingFilters.documentTypes, type];
    handleFilterChange({ documentTypes: newTypes });
  };
  const handleStateChange = (state) => {
    const newStates = pendingFilters.states.includes(state) ? pendingFilters.states.filter((s) => s !== state) : [...pendingFilters.states, state];
    handleFilterChange({ states: newStates });
  };
  const handleChamberChange = (chamber) => {
    const newChambers = pendingFilters.chambers.includes(chamber) ? pendingFilters.chambers.filter((c) => c !== chamber) : [...pendingFilters.chambers, chamber];
    handleFilterChange({ chambers: newChambers });
  };
  const handleKeywordToggle = (keyword) => {
    const newKeywords = pendingFilters.keywords.includes(keyword) ? pendingFilters.keywords.filter((k) => k !== keyword) : [...pendingFilters.keywords, keyword];
    handleFilterChange({ keywords: newKeywords });
  };
  const clearFilters = () => {
    const clearedFilters = {
      searchTerm: "",
      documentTypes: [],
      states: [],
      municipalities: [],
      chambers: [],
      keywords: [],
      dateFrom: void 0,
      dateTo: void 0
    };
    setPendingFilters(clearedFilters);
    onFiltersChange(clearedFilters);
  };
  const handleLoadSavedQuery = (savedFilters) => {
    setPendingFilters(savedFilters);
    onFiltersChange(savedFilters);
    setShowSavedQueries(false);
  };
  const hasActiveFilters = filters.documentTypes.length > 0 || filters.states.length > 0 || filters.keywords.length > 0 || filters.dateFrom || filters.dateTo || filters.searchTerm.trim();
  reactExports.useEffect(() => {
    const handleClickOutside = (e) => {
      if (suggestionsRef.current && !suggestionsRef.current.contains(e.target) && searchInputRef.current && !searchInputRef.current.contains(e.target)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "enhanced-search", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-section", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-header", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Buscar Documentos" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: "saved-queries-btn",
            onClick: () => setShowSavedQueries(true),
            "aria-label": "Consultas salvas",
            children: "📚 Consultas Salvas"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-input-container", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            ref: searchInputRef,
            type: "text",
            placeholder: "Digite palavras-chave, título ou autor...",
            value: pendingFilters.searchTerm,
            onChange: handleSearchChange,
            onKeyDown: handleKeyDown,
            onFocus: () => pendingFilters.searchTerm && setShowSuggestions(true),
            className: "search-input",
            "aria-label": "Buscar documentos"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: "search-button",
            onClick: () => debouncedFilterUpdate(pendingFilters),
            "aria-label": "Buscar",
            children: "🔍"
          }
        ),
        showSuggestions && suggestions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: suggestionsRef, className: "search-suggestions", children: suggestions.map((suggestion, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: `suggestion-item ${index === selectedSuggestionIndex ? "selected" : ""}`,
            onClick: () => selectSuggestion(suggestion),
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: `suggestion-icon ${suggestion.type}`, children: [
                suggestion.type === "keyword" && "🏷️",
                suggestion.type === "title" && "📄",
                suggestion.type === "author" && "👤",
                suggestion.type === "recent" && "🕐"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "suggestion-text", children: suggestion.text }),
              suggestion.count && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "suggestion-count", children: [
                "(",
                suggestion.count,
                ")"
              ] })
            ]
          },
          index
        )) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "quick-filters", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Filtros Rápidos" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "filter-chips", children: Array.from(facets.keywordCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([keyword, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          className: `filter-chip ${filters.keywords.includes(keyword) ? "selected" : ""}`,
          onClick: () => handleKeywordToggle(keyword),
          children: [
            keyword,
            " (",
            count,
            ")"
          ]
        },
        keyword
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        className: "advanced-toggle",
        onClick: () => setShowAdvanced(!showAdvanced),
        "aria-expanded": showAdvanced,
        children: [
          showAdvanced ? "▼" : "▶",
          " Filtros Avançados"
        ]
      }
    ),
    showAdvanced && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "advanced-filters", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Período" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "date-range", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "date",
              value: filters.dateFrom ? filters.dateFrom.toISOString().split("T")[0] : "",
              onChange: (e) => onFiltersChange(__spreadProps(__spreadValues({}, filters), {
                dateFrom: e.target.value ? new Date(e.target.value) : void 0
              })),
              "aria-label": "Data inicial"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "até" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "date",
              value: filters.dateTo ? filters.dateTo.toISOString().split("T")[0] : "",
              onChange: (e) => onFiltersChange(__spreadProps(__spreadValues({}, filters), {
                dateTo: e.target.value ? new Date(e.target.value) : void 0
              })),
              "aria-label": "Data final"
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Tipos de Documento" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "checkbox-group", children: Array.from(facets.typeCounts.entries()).sort((a, b) => b[1] - a[1]).map(([type, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.documentTypes.includes(type),
              onChange: () => handleDocumentTypeChange(type)
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "checkbox-label", children: [
            type,
            " (",
            count,
            ")"
          ] })
        ] }, type)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Origem Legislativa" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "checkbox-group", children: Array.from(facets.chamberCounts.entries()).sort((a, b) => b[1] - a[1]).map(([chamber, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-item", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: filters.chambers.includes(chamber),
              onChange: () => handleChamberChange(chamber)
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "checkbox-label", children: [
            chamber,
            " (",
            count,
            ")"
          ] })
        ] }, chamber)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Estados" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "states-grid", children: BRAZILIAN_STATES.map((state) => {
          const count = facets.stateCounts.get(state) || 0;
          if (count === 0) return null;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "state-item", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                checked: filters.states.includes(state),
                onChange: () => handleStateChange(state)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              state,
              " (",
              count,
              ")"
            ] })
          ] }, state);
        }) })
      ] })
    ] }),
    hasActiveFilters && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "active-filters", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "active-filters-header", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Filtros ativos:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "clear-all", onClick: clearFilters, children: "Limpar todos" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-tags", children: [
        filters.searchTerm && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "filter-tag", children: [
          'Busca: "',
          filters.searchTerm,
          '"',
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => onFiltersChange(__spreadProps(__spreadValues({}, filters), { searchTerm: "" })), children: "×" })
        ] }),
        filters.documentTypes.map((type) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "filter-tag", children: [
          type,
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => handleDocumentTypeChange(type), children: "×" })
        ] }, type)),
        filters.states.map((state) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "filter-tag", children: [
          state,
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => handleStateChange(state), children: "×" })
        ] }, state)),
        filters.chambers.map((chamber) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "filter-tag", children: [
          chamber,
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => handleChamberChange(chamber), children: "×" })
        ] }, chamber)),
        filters.keywords.map((keyword) => /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "filter-tag", children: [
          keyword,
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => handleKeywordToggle(keyword), children: "×" })
        ] }, keyword))
      ] })
    ] }),
    selectedState && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "selected-state", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Estado selecionado: ",
        selectedState
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: onClearSelection, children: "Limpar seleção" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SavedQueriesPanel,
      {
        isOpen: showSavedQueries,
        onClose: () => setShowSavedQueries(false),
        onLoadQuery: handleLoadSavedQuery,
        currentFilters: filters
      }
    )
  ] });
};
const TabbedSidebar = ({
  isOpen,
  onToggle,
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const [activeTab, setActiveTab] = reactExports.useState("search");
  const filteredDocuments = documents.filter((doc) => {
    if (filters.searchTerm && !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.keywords.some((keyword) => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
      return false;
    }
    if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
      return false;
    }
    if (filters.chambers.length > 0 && doc.chamber && !filters.chambers.includes(doc.chamber)) {
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
    return true;
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: `tabbed-sidebar ${isOpen ? "open" : "closed"}`,
      role: "complementary",
      "aria-labelledby": "sidebar-title",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-header", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "sidebar-title", children: "Monitor Legislativo" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              className: "sidebar-toggle",
              onClick: onToggle,
              "aria-label": isOpen ? "Fechar painel lateral" : "Abrir painel lateral",
              "aria-expanded": isOpen,
              children: isOpen ? "◀" : "▶"
            }
          )
        ] }),
        isOpen && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-tabs", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: `tab-button ${activeTab === "search" ? "active" : ""}`,
                onClick: () => setActiveTab("search"),
                "aria-selected": activeTab === "search",
                children: "🔍 Search & Filters"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: `tab-button ${activeTab === "analytics" ? "active" : ""}`,
                onClick: () => setActiveTab("analytics"),
                "aria-selected": activeTab === "analytics",
                children: "📊 Analytics"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                className: `tab-button ${activeTab === "rshiny" ? "active" : ""}`,
                onClick: () => setActiveTab("rshiny"),
                "aria-selected": activeTab === "rshiny",
                children: "🔬 R Analytics"
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-content", children: [
            activeTab === "search" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-tab", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                EnhancedSearch,
                {
                  filters,
                  onFiltersChange,
                  documents,
                  selectedState,
                  onClearSelection
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "results-summary", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Resultados" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                  filteredDocuments.length,
                  " documentos encontrados"
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "document-list", children: filteredDocuments.map((doc) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "document-item", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: doc.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "document-type", children: doc.type }),
                doc.chamber && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "document-chamber", children: [
                  "Origem: ",
                  doc.chamber
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "document-date", children: typeof doc.date === "string" ? new Date(doc.date).toLocaleDateString() : doc.date.toLocaleDateString() }),
                doc.state && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "document-location", children: [
                  "Estado: ",
                  doc.state
                ] })
              ] }, doc.id)) })
            ] }),
            activeTab === "analytics" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "analytics-tab", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DataVisualization, { documents: filteredDocuments }) }),
            activeTab === "rshiny" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rshiny-tab", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rshiny-info", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "🔬 R Analytics Dashboard" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Advanced statistical analysis and visualizations powered by R Shiny." }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rshiny-stats", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: filteredDocuments.length }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Documents" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: new Set(filteredDocuments.map((d) => d.state)).size }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "States" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-item", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: new Set(filteredDocuments.map((d) => d.type)).size }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Types" })
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rshiny-features", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Available Analyses:" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "📈 Statistical distributions" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "🗺️ Interactive geographic analysis" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "📊 Time series analysis" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "🔗 Network analysis" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "📋 Custom report generation" })
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rshiny-note", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Note:" }),
                " The R Shiny application runs independently and provides advanced analytics capabilities beyond the standard dashboard visualizations."
              ] }) })
            ] }) })
          ] })
        ] })
      ]
    }
  );
};
var TabbedSidebar_default = TabbedSidebar;
export {
  TabbedSidebar,
  TabbedSidebar_default as default
};
