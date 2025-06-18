import { j as jsxRuntimeExports } from "./index-BvirpK-b.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
import "./react-vendor-D_QSeeZk.js";
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
  const searchInputRef = reactExports.useRef(null);
  const suggestionsRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    const history = localStorage.getItem("searchHistory");
    if (history) {
      setSearchHistory(JSON.parse(history));
    }
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
    if (!filters.searchTerm || filters.searchTerm.length < 2) return [];
    const term = filters.searchTerm.toLowerCase();
    const results = [];
    Array.from(facets.keywordCounts.entries()).filter(([keyword]) => keyword.toLowerCase().includes(term)).sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([keyword, count]) => {
      results.push({ text: keyword, type: "keyword", count });
    });
    documents.filter((doc) => doc.title.toLowerCase().includes(term)).slice(0, 3).forEach((doc) => {
      results.push({ text: doc.title, type: "title" });
    });
    searchHistory.filter((search) => search.toLowerCase().includes(term) && search !== filters.searchTerm).slice(0, 2).forEach((search) => {
      results.push({ text: search, type: "recent" });
    });
    return results;
  }, [filters.searchTerm, facets, documents, searchHistory]);
  const handleSearchChange = (e) => {
    const value = e.target.value;
    onFiltersChange({ ...filters, searchTerm: value });
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
    onFiltersChange({ ...filters, searchTerm: suggestion.text });
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
    const newTypes = filters.documentTypes.includes(type) ? filters.documentTypes.filter((t) => t !== type) : [...filters.documentTypes, type];
    onFiltersChange({ ...filters, documentTypes: newTypes });
  };
  const handleStateChange = (state) => {
    const newStates = filters.states.includes(state) ? filters.states.filter((s) => s !== state) : [...filters.states, state];
    onFiltersChange({ ...filters, states: newStates });
  };
  const handleChamberChange = (chamber) => {
    const newChambers = filters.chambers.includes(chamber) ? filters.chambers.filter((c) => c !== chamber) : [...filters.chambers, chamber];
    onFiltersChange({ ...filters, chambers: newChambers });
  };
  const handleKeywordToggle = (keyword) => {
    const newKeywords = filters.keywords.includes(keyword) ? filters.keywords.filter((k) => k !== keyword) : [...filters.keywords, keyword];
    onFiltersChange({ ...filters, keywords: newKeywords });
  };
  const clearFilters = () => {
    onFiltersChange({
      searchTerm: "",
      documentTypes: [],
      states: [],
      municipalities: [],
      keywords: [],
      dateFrom: void 0,
      dateTo: void 0
    });
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Buscar Documentos" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-input-container", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            ref: searchInputRef,
            type: "text",
            placeholder: "Digite palavras-chave, título ou autor...",
            value: filters.searchTerm,
            onChange: handleSearchChange,
            onKeyDown: handleKeyDown,
            onFocus: () => filters.searchTerm && setShowSuggestions(true),
            className: "search-input",
            "aria-label": "Buscar documentos"
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
              onChange: (e) => onFiltersChange({
                ...filters,
                dateFrom: e.target.value ? new Date(e.target.value) : void 0
              }),
              "aria-label": "Data inicial"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "até" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "date",
              value: filters.dateTo ? filters.dateTo.toISOString().split("T")[0] : "",
              onChange: (e) => onFiltersChange({
                ...filters,
                dateTo: e.target.value ? new Date(e.target.value) : void 0
              }),
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => onFiltersChange({ ...filters, searchTerm: "" }), children: "×" })
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
    ] })
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
            activeTab === "analytics" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "analytics-tab", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DataVisualization, { documents: filteredDocuments }) })
          ] })
        ] })
      ]
    }
  );
};
export {
  TabbedSidebar,
  TabbedSidebar as default
};
