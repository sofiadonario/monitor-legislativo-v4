import { j as jsxRuntimeExports } from "./index-D3xkQ84y.js";
import { r as reactExports, R as React } from "./leaflet-vendor-BcXhkSxI.js";
import { G as GlassCard_default } from "./GlassCard-etifr883.js";
import "./react-vendor-CSPBeBBz.js";
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
const VocabularyNavigator = ({
  onConceptSelect,
  onQueryExpansion,
  className = "",
  language = "pt",
  initialScheme = "transport"
}) => {
  var _a;
  const [selectedConcept, setSelectedConcept] = reactExports.useState(null);
  const [conceptHierarchy, setConceptHierarchy] = reactExports.useState(null);
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [searchResults, setSearchResults] = reactExports.useState([]);
  const [currentScheme, setCurrentScheme] = reactExports.useState(initialScheme);
  const [breadcrumb, setBreadcrumb] = reactExports.useState([]);
  const [expandedNodes, setExpandedNodes] = reactExports.useState(/* @__PURE__ */ new Set());
  const [showSearch, setShowSearch] = reactExports.useState(false);
  const [isLoading, setIsLoading] = reactExports.useState(false);
  const [vocabularyOverview, setVocabularyOverview] = reactExports.useState(null);
  const mockVocabulary = {
    transport: {
      scheme: "transport",
      total_concepts: 25,
      max_depth: 3,
      root_concepts: [
        {
          uri: "http://vocab.lexml.gov.br/transport/modal",
          label: "Modal de Transporte",
          children_count: 4
        }
      ],
      top_level_categories: 1
    },
    concepts: {
      "http://vocab.lexml.gov.br/transport/modal": {
        uri: "http://vocab.lexml.gov.br/transport/modal",
        pref_label: { pt: "Modal de Transporte", en: "Transport Mode" },
        alt_labels: { pt: ["Modalidade", "Modo de Transporte"] },
        definition: { pt: "Categorias de modalidades de transporte" },
        concept_scheme: "transport",
        broader: [],
        narrower: [
          "http://vocab.lexml.gov.br/transport/modal/rodoviario",
          "http://vocab.lexml.gov.br/transport/modal/ferroviario",
          "http://vocab.lexml.gov.br/transport/modal/aquaviario",
          "http://vocab.lexml.gov.br/transport/modal/aereo"
        ],
        related: []
      },
      "http://vocab.lexml.gov.br/transport/modal/rodoviario": {
        uri: "http://vocab.lexml.gov.br/transport/modal/rodoviario",
        pref_label: { pt: "Transporte Rodoviário", en: "Road Transport" },
        alt_labels: { pt: ["Modal Rodoviário", "Transporte por Estradas"] },
        definition: { pt: "Transporte realizado através de rodovias e estradas" },
        concept_scheme: "transport",
        broader: ["http://vocab.lexml.gov.br/transport/modal"],
        narrower: [
          "http://vocab.lexml.gov.br/transport/modal/rodoviario/cargas",
          "http://vocab.lexml.gov.br/transport/modal/rodoviario/passageiros"
        ],
        related: ["http://vocab.lexml.gov.br/entities/antt"]
      },
      "http://vocab.lexml.gov.br/transport/modal/ferroviario": {
        uri: "http://vocab.lexml.gov.br/transport/modal/ferroviario",
        pref_label: { pt: "Transporte Ferroviário", en: "Railway Transport" },
        alt_labels: { pt: ["Modal Ferroviário", "Transporte por Trens"] },
        definition: { pt: "Transporte realizado através de ferrovias" },
        concept_scheme: "transport",
        broader: ["http://vocab.lexml.gov.br/transport/modal"],
        narrower: [
          "http://vocab.lexml.gov.br/transport/modal/ferroviario/cargas",
          "http://vocab.lexml.gov.br/transport/modal/ferroviario/passageiros"
        ],
        related: []
      },
      "http://vocab.lexml.gov.br/transport/modal/aquaviario": {
        uri: "http://vocab.lexml.gov.br/transport/modal/aquaviario",
        pref_label: { pt: "Transporte Aquaviário", en: "Water Transport" },
        alt_labels: { pt: ["Modal Aquaviário", "Transporte Marítimo"] },
        definition: { pt: "Transporte realizado através de vias aquáticas" },
        concept_scheme: "transport",
        broader: ["http://vocab.lexml.gov.br/transport/modal"],
        narrower: [
          "http://vocab.lexml.gov.br/transport/modal/aquaviario/maritimo",
          "http://vocab.lexml.gov.br/transport/modal/aquaviario/fluvial"
        ],
        related: ["http://vocab.lexml.gov.br/entities/antaq"]
      },
      "http://vocab.lexml.gov.br/transport/modal/aereo": {
        uri: "http://vocab.lexml.gov.br/transport/modal/aereo",
        pref_label: { pt: "Transporte Aéreo", en: "Air Transport" },
        alt_labels: { pt: ["Modal Aéreo", "Aviação"] },
        definition: { pt: "Transporte realizado através de aeronaves" },
        concept_scheme: "transport",
        broader: ["http://vocab.lexml.gov.br/transport/modal"],
        narrower: [
          "http://vocab.lexml.gov.br/transport/modal/aereo/comercial",
          "http://vocab.lexml.gov.br/transport/modal/aereo/geral"
        ],
        related: ["http://vocab.lexml.gov.br/entities/anac"]
      }
    }
  };
  reactExports.useEffect(() => {
    setVocabularyOverview(mockVocabulary[currentScheme]);
  }, [currentScheme]);
  reactExports.useEffect(() => {
    if (selectedConcept) {
      loadConceptHierarchy(selectedConcept.uri);
    }
  }, [selectedConcept]);
  const loadConceptHierarchy = (conceptUri) => __async(null, null, function* () {
    setIsLoading(true);
    try {
      yield new Promise((resolve) => setTimeout(resolve, 300));
      const concept = mockVocabulary.concepts[conceptUri];
      if (concept) {
        const hierarchy = {
          concept,
          path: buildConceptPath(concept),
          children: concept.narrower.map((uri) => mockVocabulary.concepts[uri]).filter(Boolean),
          parent: concept.broader.length > 0 ? mockVocabulary.concepts[concept.broader[0]] : void 0,
          siblings: [],
          depth: calculateDepth(concept),
          is_root: concept.broader.length === 0,
          is_leaf: concept.narrower.length === 0
        };
        setConceptHierarchy(hierarchy);
        setBreadcrumb(hierarchy.path.map((uri) => mockVocabulary.concepts[uri]).filter(Boolean));
      }
    } catch (error) {
      console.error("Error loading concept hierarchy:", error);
    } finally {
      setIsLoading(false);
    }
  });
  const buildConceptPath = (concept) => {
    const path = [concept.uri];
    let current = concept;
    while (current.broader.length > 0) {
      const parentUri = current.broader[0];
      const parent = mockVocabulary.concepts[parentUri];
      if (parent) {
        path.unshift(parentUri);
        current = parent;
      } else {
        break;
      }
    }
    return path;
  };
  const calculateDepth = (concept) => {
    let depth = 0;
    let current = concept;
    while (current.broader.length > 0) {
      depth++;
      const parentUri = current.broader[0];
      const parent = mockVocabulary.concepts[parentUri];
      if (parent) {
        current = parent;
      } else {
        break;
      }
    }
    return depth;
  };
  const searchConcepts = (query) => __async(null, null, function* () {
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }
    setIsLoading(true);
    try {
      yield new Promise((resolve) => setTimeout(resolve, 200));
      const queryLower = query.toLowerCase();
      const results = [];
      Object.values(mockVocabulary.concepts).forEach((concept) => {
        const prefLabel = concept.pref_label[language] || concept.pref_label.pt || "";
        const altLabels = concept.alt_labels[language] || concept.alt_labels.pt || [];
        if (prefLabel.toLowerCase() === queryLower) {
          results.push({
            concept,
            match_type: "exact",
            score: 1,
            matched_label: prefLabel
          });
        } else if (prefLabel.toLowerCase().startsWith(queryLower)) {
          results.push({
            concept,
            match_type: "prefix",
            score: 0.9,
            matched_label: prefLabel
          });
        } else if (prefLabel.toLowerCase().includes(queryLower)) {
          results.push({
            concept,
            match_type: "contains",
            score: 0.7,
            matched_label: prefLabel
          });
        } else {
          for (const altLabel of altLabels) {
            if (altLabel.toLowerCase().includes(queryLower)) {
              results.push({
                concept,
                match_type: "alternative",
                score: 0.6,
                matched_label: altLabel
              });
              break;
            }
          }
        }
      });
      results.sort((a, b) => b.score - a.score);
      setSearchResults(results.slice(0, 10));
    } catch (error) {
      console.error("Error searching concepts:", error);
    } finally {
      setIsLoading(false);
    }
  });
  const handleConceptSelect = (concept) => {
    setSelectedConcept(concept);
    setSearchQuery("");
    setSearchResults([]);
    setShowSearch(false);
    if (onConceptSelect) {
      onConceptSelect(concept);
    }
  };
  const generateQueryExpansion = (concept) => {
    const expansion = {
      original: [concept.pref_label[language] || concept.pref_label.pt || ""],
      narrower: [],
      broader: [],
      related: [],
      synonyms: concept.alt_labels[language] || concept.alt_labels.pt || []
    };
    concept.narrower.forEach((uri) => {
      const narrowerConcept = mockVocabulary.concepts[uri];
      if (narrowerConcept) {
        expansion.narrower.push(narrowerConcept.pref_label[language] || narrowerConcept.pref_label.pt || "");
      }
    });
    concept.broader.forEach((uri) => {
      const broaderConcept = mockVocabulary.concepts[uri];
      if (broaderConcept) {
        expansion.broader.push(broaderConcept.pref_label[language] || broaderConcept.pref_label.pt || "");
      }
    });
    concept.related.forEach((uri) => {
      const relatedConcept = mockVocabulary.concepts[uri];
      if (relatedConcept) {
        expansion.related.push(relatedConcept.pref_label[language] || relatedConcept.pref_label.pt || "");
      }
    });
    if (onQueryExpansion) {
      onQueryExpansion(expansion);
    }
    return expansion;
  };
  const toggleNodeExpansion = (uri) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(uri)) {
      newExpanded.delete(uri);
    } else {
      newExpanded.add(uri);
    }
    setExpandedNodes(newExpanded);
  };
  const renderConceptNode = (concept, depth = 0) => {
    const hasChildren = concept.narrower.length > 0;
    const isExpanded = expandedNodes.has(concept.uri);
    const isSelected = (selectedConcept == null ? void 0 : selectedConcept.uri) === concept.uri;
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          className: `
            flex items-center gap-2 p-2 rounded cursor-pointer transition-colors
            ${isSelected ? "bg-blue-100 text-blue-800" : "hover:bg-gray-50"}
          `,
          style: { paddingLeft: `${depth * 20 + 8}px` },
          onClick: () => handleConceptSelect(concept),
          children: [
            hasChildren && /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                onClick: (e) => {
                  e.stopPropagation();
                  toggleNodeExpansion(concept.uri);
                },
                className: "p-1 hover:bg-gray-200 rounded",
                children: isExpanded ? "🔽" : "▶️"
              }
            ),
            !hasChildren && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "w-6" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex-1 font-medium", children: concept.pref_label[language] || concept.pref_label.pt }),
            concept.narrower.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded", children: concept.narrower.length })
          ]
        }
      ),
      hasChildren && isExpanded && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: concept.narrower.map((childUri) => {
        const childConcept = mockVocabulary.concepts[childUri];
        return childConcept ? renderConceptNode(childConcept, depth + 1) : null;
      }) })
    ] }, concept.uri);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `vocabulary-navigator ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(GlassCard_default, { variant: "academic", className: "mb-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between items-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-xl font-bold text-gray-800", children: "Navegador de Vocabulário SKOS" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600", children: "Explore hierarquias de conceitos legislativos brasileiros" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setShowSearch(!showSearch),
            className: `glass-button-secondary px-4 py-2 ${showSearch ? "bg-blue-50" : ""}`,
            children: "🔍 Buscar"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => generateQueryExpansion(selectedConcept),
            disabled: !selectedConcept,
            className: "glass-button-primary px-4 py-2 disabled:opacity-50",
            children: "🔄 Expandir"
          }
        )
      ] })
    ] }) }),
    showSearch && /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "light", className: "mb-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "text",
            value: searchQuery,
            onChange: (e) => {
              setSearchQuery(e.target.value);
              searchConcepts(e.target.value);
            },
            placeholder: "Buscar conceitos no vocabulário...",
            className: "glass-input pr-10"
          }
        ),
        isLoading && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute right-3 top-1/2 transform -translate-y-1/2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "animate-spin w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full" }) })
      ] }),
      searchResults.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 max-h-60 overflow-y-auto", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm font-medium text-gray-600 mb-2", children: [
          "Resultados da busca (",
          searchResults.length,
          ")"
        ] }),
        searchResults.map((result, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            onClick: () => handleConceptSelect(result.concept),
            className: "flex items-center justify-between p-3 border border-gray-200 rounded mb-2 cursor-pointer hover:bg-gray-50",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium", children: result.matched_label }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm text-gray-600", children: result.concept.definition[language] || result.concept.definition.pt })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                      px-2 py-1 rounded text-xs font-medium
                      ${result.match_type === "exact" ? "bg-green-100 text-green-700" : result.match_type === "prefix" ? "bg-blue-100 text-blue-700" : result.match_type === "contains" ? "bg-yellow-100 text-yellow-700" : "bg-gray-100 text-gray-700"}
                    `, children: result.match_type }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-gray-500", children: [
                  Math.round(result.score * 100),
                  "%"
                ] })
              ] })
            ]
          },
          index
        ))
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "lg:col-span-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "research", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-bold text-lg mb-4", children: "Hierarquia de Conceitos" }),
        breadcrumb.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 p-3 bg-blue-50 rounded-lg", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-blue-700 mb-1", children: "Caminho:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-2 text-sm", children: breadcrumb.map((concept, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(React.Fragment, { children: [
            index > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-gray-400", children: "→" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                onClick: () => handleConceptSelect(concept),
                className: "text-blue-600 hover:text-blue-800 hover:underline",
                children: concept.pref_label[language] || concept.pref_label.pt
              }
            )
          ] }, concept.uri)) })
        ] }),
        vocabularyOverview && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-4 p-3 bg-gray-50 rounded-lg", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 md:grid-cols-4 gap-4 text-center text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-blue-600", children: vocabularyOverview.total_concepts }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Conceitos" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-green-600", children: vocabularyOverview.max_depth }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Níveis" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-purple-600", children: vocabularyOverview.top_level_categories }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Categorias" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-orange-600", children: currentScheme }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Esquema" })
          ] })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-96 overflow-y-auto", children: vocabularyOverview == null ? void 0 : vocabularyOverview.root_concepts.map((rootConcept) => {
          const concept = mockVocabulary.concepts[rootConcept.uri];
          return concept ? renderConceptNode(concept) : null;
        }) })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "analysis", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-bold text-lg mb-4", children: "Detalhes do Conceito" }),
        selectedConcept ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-bold text-lg text-blue-800", children: selectedConcept.pref_label[language] || selectedConcept.pref_label.pt }),
            selectedConcept.notation && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-gray-600", children: [
              "Notação: ",
              selectedConcept.notation
            ] })
          ] }),
          selectedConcept.definition[language] && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-gray-700 mb-1", children: "Definição:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm text-gray-600", children: selectedConcept.definition[language] || selectedConcept.definition.pt })
          ] }),
          ((_a = selectedConcept.alt_labels[language]) == null ? void 0 : _a.length) > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-gray-700 mb-1", children: "Termos alternativos:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-1", children: selectedConcept.alt_labels[language].map((label) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge text-xs", children: label }, label)) })
          ] }),
          conceptHierarchy && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            conceptHierarchy.parent && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-gray-700 mb-1", children: "Conceito superior:" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  onClick: () => handleConceptSelect(conceptHierarchy.parent),
                  className: "text-sm text-blue-600 hover:text-blue-800 hover:underline",
                  children: conceptHierarchy.parent.pref_label[language] || conceptHierarchy.parent.pref_label.pt
                }
              )
            ] }),
            conceptHierarchy.children.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-gray-700 mb-1", children: "Conceitos subordinados:" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-1", children: conceptHierarchy.children.map((child) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  onClick: () => handleConceptSelect(child),
                  className: "block text-sm text-blue-600 hover:text-blue-800 hover:underline",
                  children: child.pref_label[language] || child.pref_label.pt
                },
                child.uri
              )) })
            ] }),
            selectedConcept.related.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-gray-700 mb-1", children: "Conceitos relacionados:" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-1", children: selectedConcept.related.map((relatedUri) => {
                const relatedConcept = mockVocabulary.concepts[relatedUri];
                return relatedConcept ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    onClick: () => handleConceptSelect(relatedConcept),
                    className: "block text-sm text-purple-600 hover:text-purple-800 hover:underline",
                    children: relatedConcept.pref_label[language] || relatedConcept.pref_label.pt
                  },
                  relatedUri
                ) : null;
              }) })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "pt-3 border-t border-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 gap-2 text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-blue-600", children: conceptHierarchy.depth }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Nível" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-green-600", children: conceptHierarchy.children.length }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Filhos" })
              ] })
            ] }) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "pt-3 border-t border-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => generateQueryExpansion(selectedConcept),
              className: "glass-button-primary w-full py-2 text-sm",
              children: "🔄 Gerar Expansão de Consulta"
            }
          ) })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center py-8 text-gray-500", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-2", children: "📚" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: "Selecione um conceito para ver detalhes" })
        ] })
      ] }) })
    ] })
  ] });
};
var VocabularyNavigator_default = VocabularyNavigator;
export {
  VocabularyNavigator_default as default
};
