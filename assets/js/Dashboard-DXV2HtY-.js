const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/OptimizedMap-CEsoKxeF.js","assets/js/index-1a7TlnNV.js","assets/js/react-vendor-D_QSeeZk.js","assets/js/leaflet-vendor-HKOewaEh.js","assets/css/index-B3keVYzP.css","assets/css/OptimizedMap-Dlna1-ep.css","assets/js/Sidebar-B2r6WfeS.js","assets/css/Sidebar-TjMzppEy.css","assets/js/ExportPanel-B7qivXWD.js","assets/js/utils-C418i17z.js","assets/css/ExportPanel-rPKiQ0eQ.css"])))=>i.map(i=>d[i]);
import { j as jsxRuntimeExports, L as LoadingSpinner, _ as __vitePreload } from "./index-1a7TlnNV.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
import "./react-vendor-D_QSeeZk.js";
const mockLegislativeData = [
  {
    id: "1",
    title: "Lei Federal nº 14.000/2020 - Modernização do Transporte Rodoviário",
    type: "lei",
    number: "14.000/2020",
    date: "2020-05-15",
    summary: "Estabelece diretrizes para a modernização do transporte rodoviário de cargas, incluindo implementação de tecnologias digitais e sistemas de rastreamento.",
    state: "SP",
    municipality: "São Paulo",
    keywords: ["transporte", "rodoviário", "modernização", "tecnologia"],
    source: "Diário Oficial da União",
    citation: "BRASIL. Lei nº 14.000, de 15 de maio de 2020. Diário Oficial da União, Brasília, DF, 16 maio 2020.",
    url: "https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2020/lei/l14000.htm"
  },
  {
    id: "2",
    title: "Decreto Estadual SP nº 65.500/2021 - Regulamentação de Veículos Autônomos",
    type: "decreto",
    number: "65.500/2021",
    date: "2021-03-22",
    summary: "Regulamenta a circulação de veículos autônomos em vias estaduais de São Paulo, estabelecendo critérios de segurança e licenciamento.",
    state: "SP",
    municipality: "São Paulo",
    keywords: ["veículos autônomos", "regulamentação", "segurança", "tecnologia"],
    source: "Diário Oficial do Estado de São Paulo",
    citation: "SÃO PAULO. Decreto nº 65.500, de 22 de março de 2021. Diário Oficial do Estado, São Paulo, SP, 23 mar. 2021.",
    url: "https://www.al.sp.gov.br/repositorio/legislacao/decreto/2021/decreto-65500-22.03.2021.html"
  },
  {
    id: "3",
    title: "Portaria ANTT nº 3.200/2021 - Cadastro Nacional de Transportadores",
    type: "portaria",
    number: "3.200/2021",
    date: "2021-07-08",
    summary: "Institui o Cadastro Nacional de Transportadores de Cargas, unificando registros e facilitando o controle regulatório do setor.",
    state: "DF",
    keywords: ["ANTT", "transportadores", "cadastro", "regulamentação"],
    source: "Diário Oficial da União",
    citation: "AGÊNCIA NACIONAL DE TRANSPORTES TERRESTRES. Portaria nº 3.200, de 8 de julho de 2021. Diário Oficial da União, Brasília, DF, 9 jul. 2021.",
    url: "https://www.antt.gov.br/portarias/2021/portaria3200.html"
  },
  {
    id: "4",
    title: "Lei Estadual RJ nº 9.100/2020 - Transporte Sustentável",
    type: "lei",
    number: "9.100/2020",
    date: "2020-11-30",
    summary: "Estabelece incentivos fiscais para empresas de transporte que adotem tecnologias limpas e sustentáveis no estado do Rio de Janeiro.",
    state: "RJ",
    municipality: "Rio de Janeiro",
    keywords: ["sustentabilidade", "incentivos fiscais", "tecnologias limpas"],
    source: "Diário Oficial do Estado do Rio de Janeiro",
    citation: "RIO DE JANEIRO. Lei nº 9.100, de 30 de novembro de 2020. Diário Oficial do Estado, Rio de Janeiro, RJ, 1 dez. 2020."
  },
  {
    id: "5",
    title: "Resolução CONTRAN nº 800/2021 - Segurança em Rodovias",
    type: "resolucao",
    number: "800/2021",
    date: "2021-09-15",
    summary: "Define novas normas de segurança para o transporte rodoviário, incluindo equipamentos obrigatórios e procedimentos de fiscalização.",
    keywords: ["CONTRAN", "segurança", "fiscalização", "equipamentos"],
    source: "Diário Oficial da União",
    citation: "CONSELHO NACIONAL DE TRÂNSITO. Resolução nº 800, de 15 de setembro de 2021. Diário Oficial da União, Brasília, DF, 16 set. 2021."
  },
  {
    id: "6",
    title: "Medida Provisória nº 1.050/2021 - Marco do Transporte Digital",
    type: "medida_provisoria",
    number: "1.050/2021",
    date: "2021-04-12",
    summary: "Institui o Marco Legal do Transporte Digital, regulamentando plataformas de transporte e estabelecendo direitos dos usuários.",
    keywords: ["marco legal", "transporte digital", "plataformas", "direitos dos usuários"],
    source: "Diário Oficial da União",
    citation: "BRASIL. Medida Provisória nº 1.050, de 12 de abril de 2021. Diário Oficial da União, Brasília, DF, 13 abr. 2021."
  },
  {
    id: "7",
    title: "Lei Estadual MG nº 23.500/2019 - Corredores de Transporte",
    type: "lei",
    number: "23.500/2019",
    date: "2019-12-20",
    summary: "Autoriza a criação de corredores exclusivos de transporte de cargas em rodovias estaduais de Minas Gerais.",
    state: "MG",
    municipality: "Belo Horizonte",
    keywords: ["corredores", "rodovias estaduais", "cargas"],
    source: "Diário Oficial do Estado de Minas Gerais",
    citation: "MINAS GERAIS. Lei nº 23.500, de 20 de dezembro de 2019. Diário Oficial do Estado, Belo Horizonte, MG, 21 dez. 2019."
  },
  {
    id: "8",
    title: "Decreto Federal nº 10.800/2021 - Política Nacional de Logística",
    type: "decreto",
    number: "10.800/2021",
    date: "2021-08-05",
    summary: "Institui a Política Nacional de Logística de Transportes, integrando modais e otimizando a infraestrutura nacional.",
    keywords: ["política nacional", "logística", "modais", "infraestrutura"],
    source: "Diário Oficial da União",
    citation: "BRASIL. Decreto nº 10.800, de 5 de agosto de 2021. Diário Oficial da União, Brasília, DF, 6 ago. 2021."
  },
  {
    id: "9",
    title: "Portaria DNIT nº 1.500/2020 - Manutenção de Rodovias",
    type: "portaria",
    number: "1.500/2020",
    date: "2020-10-18",
    summary: "Estabelece novos padrões para manutenção preventiva de rodovias federais, priorizando a segurança do transporte de cargas.",
    keywords: ["DNIT", "manutenção", "rodovias federais", "segurança"],
    source: "Diário Oficial da União",
    citation: "DEPARTAMENTO NACIONAL DE INFRAESTRUTURA DE TRANSPORTES. Portaria nº 1.500, de 18 de outubro de 2020. Diário Oficial da União, Brasília, DF, 19 out. 2020."
  },
  {
    id: "10",
    title: "Lei Estadual RS nº 15.200/2018 - Transporte Intermodal",
    type: "lei",
    number: "15.200/2018",
    date: "2018-06-25",
    summary: "Promove a integração entre modais de transporte no Rio Grande do Sul, incentivando o uso de ferrovias e hidrovias.",
    state: "RS",
    municipality: "Porto Alegre",
    keywords: ["intermodal", "ferrovias", "hidrovias", "integração"],
    source: "Diário Oficial do Estado do Rio Grande do Sul",
    citation: "RIO GRANDE DO SUL. Lei nº 15.200, de 25 de junho de 2018. Diário Oficial do Estado, Porto Alegre, RS, 26 jun. 2018."
  },
  {
    id: "11",
    title: "Resolução ANTT nº 5.850/2021 - Transporte de Produtos Perigosos",
    type: "resolucao",
    number: "5.850/2021",
    date: "2021-01-30",
    summary: "Atualiza as normas para transporte rodoviário de produtos perigosos, incluindo novas classificações e equipamentos de segurança.",
    keywords: ["produtos perigosos", "segurança", "classificações", "equipamentos"],
    source: "Diário Oficial da União",
    citation: "AGÊNCIA NACIONAL DE TRANSPORTES TERRESTRES. Resolução nº 5.850, de 30 de janeiro de 2021. Diário Oficial da União, Brasília, DF, 31 jan. 2021."
  },
  {
    id: "12",
    title: "Decreto Estadual PR nº 8.900/2020 - Pedágios Eletrônicos",
    type: "decreto",
    number: "8.900/2020",
    date: "2020-08-14",
    summary: "Regulamenta a implementação de sistemas de pedágio eletrônico em rodovias estaduais do Paraná.",
    state: "PR",
    municipality: "Curitiba",
    keywords: ["pedágio eletrônico", "rodovias estaduais", "implementação"],
    source: "Diário Oficial do Estado do Paraná",
    citation: "PARANÁ. Decreto nº 8.900, de 14 de agosto de 2020. Diário Oficial do Estado, Curitiba, PR, 15 ago. 2020."
  },
  {
    id: "13",
    title: "Lei Federal nº 13.950/2019 - Cabotagem de Cargas",
    type: "lei",
    number: "13.950/2019",
    date: "2019-11-08",
    summary: "Moderniza o marco legal da cabotagem, facilitando o transporte marítimo de cargas entre portos brasileiros.",
    keywords: ["cabotagem", "transporte marítimo", "portos", "marco legal"],
    source: "Diário Oficial da União",
    citation: "BRASIL. Lei nº 13.950, de 8 de novembro de 2019. Diário Oficial da União, Brasília, DF, 11 nov. 2019."
  },
  {
    id: "14",
    title: "Portaria MT nº 2.100/2021 - Planejamento Logístico",
    type: "portaria",
    number: "2.100/2021",
    date: "2021-05-20",
    summary: "Institui o Sistema Nacional de Planejamento Logístico, integrando dados de transporte e facilitando a tomada de decisões.",
    keywords: ["planejamento logístico", "sistema nacional", "dados", "tomada de decisões"],
    source: "Diário Oficial da União",
    citation: "MINISTÉRIO DA INFRAESTRUTURA. Portaria nº 2.100, de 20 de maio de 2021. Diário Oficial da União, Brasília, DF, 21 maio 2021."
  },
  {
    id: "15",
    title: "Lei Estadual BA nº 14.800/2021 - Corredores Logísticos",
    type: "lei",
    number: "14.800/2021",
    date: "2021-02-28",
    summary: "Cria corredores logísticos estratégicos na Bahia, conectando portos e centros de produção agrícola.",
    state: "BA",
    municipality: "Salvador",
    keywords: ["corredores logísticos", "portos", "agricultura", "conexão"],
    source: "Diário Oficial do Estado da Bahia",
    citation: "BAHIA. Lei nº 14.800, de 28 de fevereiro de 2021. Diário Oficial do Estado, Salvador, BA, 1 mar. 2021."
  }
];
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
const OptimizedMap = reactExports.lazy(() => __vitePreload(() => import("./OptimizedMap-CEsoKxeF.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0).then((module) => ({ default: module.default })));
const Sidebar = reactExports.lazy(() => __vitePreload(() => import("./Sidebar-B2r6WfeS.js"), true ? __vite__mapDeps([6,1,2,3,4,7]) : void 0).then((module) => ({ default: module.default })));
const ExportPanel = reactExports.lazy(() => __vitePreload(() => import("./ExportPanel-B7qivXWD.js"), true ? __vite__mapDeps([8,1,2,3,4,9,10]) : void 0).then((module) => ({ default: module.default })));
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
  const [documents] = reactExports.useState(mockLegislativeData);
  const { sidebarOpen, exportPanelOpen, selectedState, selectedMunicipality, filters } = state;
  const mainContentRef = reactExports.useRef(null);
  const skipLinkRef = reactExports.useRef(null);
  useKeyboardNavigation();
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
      if (filters.dateFrom && doc.date < filters.dateFrom) {
        return false;
      }
      if (filters.dateTo && doc.date > filters.dateTo) {
        return false;
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
      Sidebar,
      {
        isOpen: sidebarOpen,
        onToggle: toggleSidebar,
        filters,
        onFiltersChange: (newFilters) => dispatch({ type: "UPDATE_FILTERS", payload: newFilters }),
        documents: filteredDocuments,
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
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stats", role: "status", "aria-live": "polite", children: [
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
              ] })
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
export {
  Dashboard as default
};
