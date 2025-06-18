import { j as jsxRuntimeExports } from "./index-1a7TlnNV.js";
import "./react-vendor-D_QSeeZk.js";
import "./leaflet-vendor-HKOewaEh.js";
const documentTypes = [
  { id: "lei", label: "Leis" },
  { id: "decreto", label: "Decretos" },
  { id: "portaria", label: "Portarias" },
  { id: "resolucao", label: "Resoluções" },
  { id: "medida_provisoria", label: "Medidas Provisórias" }
];
const Sidebar = ({
  isOpen,
  onToggle,
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const handleSearchChange = (e) => {
    onFiltersChange({
      ...filters,
      searchTerm: e.target.value
    });
  };
  const handleDateFromChange = (e) => {
    onFiltersChange({
      ...filters,
      dateFrom: e.target.value
    });
  };
  const handleDateToChange = (e) => {
    onFiltersChange({
      ...filters,
      dateTo: e.target.value
    });
  };
  const handleDocumentTypeChange = (type, checked) => {
    const newTypes = checked ? [...filters.documentTypes, type] : filters.documentTypes.filter((t) => t !== type);
    onFiltersChange({
      ...filters,
      documentTypes: newTypes
    });
  };
  const filteredDocuments = documents.filter((doc) => {
    if (filters.searchTerm && !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) && !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase())) {
      return false;
    }
    if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
      return false;
    }
    if (filters.dateFrom && doc.date < filters.dateFrom) {
      return false;
    }
    if (filters.dateTo && doc.date > filters.dateTo) {
      return false;
    }
    if (selectedState && doc.state !== selectedState) {
      return false;
    }
    return true;
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `sidebar ${isOpen ? "open" : "closed"}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-header", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Mapa Legislativo Acadêmico" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "toggle-btn", onClick: onToggle, "aria-label": "Toggle sidebar", children: isOpen ? "←" : "→" })
      ] }),
      isOpen && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-content", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "search-section", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Busca" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "text",
              placeholder: "Buscar por título ou resumo...",
              value: filters.searchTerm,
              onChange: handleSearchChange,
              className: "search-input"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Período" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "date-inputs", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: filters.dateFrom || "",
                onChange: handleDateFromChange,
                className: "date-input",
                "aria-label": "Data de início"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "até" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "date",
                value: filters.dateTo || "",
                onChange: handleDateToChange,
                className: "date-input",
                "aria-label": "Data de fim"
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "filter-section", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Tipo de Documento" }),
          documentTypes.map((type) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "checkbox-label", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                checked: filters.documentTypes.includes(type.id),
                onChange: (e) => handleDocumentTypeChange(type.id, e.target.checked)
              }
            ),
            type.label
          ] }, type.id))
        ] }),
        selectedState && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "selected-state", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Estado Selecionado" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: selectedState }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: onClearSelection, className: "clear-btn", children: "Limpar Seleção" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "results-summary", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Resultados" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
            filteredDocuments.length,
            " documentos encontrados"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "document-list", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Documentos" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "document-items", children: [
            filteredDocuments.slice(0, 10).map((doc) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "document-item", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: doc.title }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "doc-meta", children: [
                doc.type,
                " • ",
                doc.number,
                " • ",
                new Date(doc.date).toLocaleDateString("pt-BR")
              ] }),
              doc.state && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "doc-location", children: [
                "Estado: ",
                doc.state
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "doc-summary", children: [
                doc.summary.slice(0, 100),
                "..."
              ] }),
              doc.url && /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: doc.url, target: "_blank", rel: "noopener noreferrer", className: "doc-link", children: "Ver documento" })
            ] }, doc.id)),
            filteredDocuments.length > 10 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "more-results", children: [
              "E mais ",
              filteredDocuments.length - 10,
              " documentos..."
            ] })
          ] })
        ] })
      ] })
    ] }),
    isOpen && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sidebar-overlay", onClick: onToggle })
  ] });
};
export {
  Sidebar as default
};
