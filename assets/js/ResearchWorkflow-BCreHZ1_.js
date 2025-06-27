import { j as jsxRuntimeExports } from "./index-D3xkQ84y.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { G as GlassCard_default } from "./GlassCard-etifr883.js";
import "./react-vendor-CSPBeBBz.js";
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
const ResearchWorkflow = ({
  className = "",
  onProjectChange
}) => {
  const [currentProject, setCurrentProject] = reactExports.useState(null);
  const [projects, setProjects] = reactExports.useState([]);
  const [activeTab, setActiveTab] = reactExports.useState("overview");
  const [selectedNote, setSelectedNote] = reactExports.useState(null);
  const [isCreatingProject, setIsCreatingProject] = reactExports.useState(false);
  const [isCreatingNote, setIsCreatingNote] = reactExports.useState(false);
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [filterTags, setFilterTags] = reactExports.useState([]);
  const [showAdvancedFilters, setShowAdvancedFilters] = reactExports.useState(false);
  reactExports.useRef(null);
  reactExports.useEffect(() => {
    const savedProjects = localStorage.getItem("research_projects");
    if (savedProjects) {
      try {
        const parsedProjects = JSON.parse(savedProjects);
        setProjects(parsedProjects);
        if (parsedProjects.length > 0 && !currentProject) {
          setCurrentProject(parsedProjects[0]);
        }
      } catch (error) {
        console.error("Error loading research projects:", error);
      }
    }
  }, []);
  const saveProjects = (updatedProjects) => {
    setProjects(updatedProjects);
    localStorage.setItem("research_projects", JSON.stringify(updatedProjects));
  };
  const createNewProject = (projectData) => {
    const newProject = {
      id: `project_${Date.now()}`,
      title: projectData.title || "Novo Projeto de Pesquisa",
      description: projectData.description || "",
      status: "planning",
      created_date: (/* @__PURE__ */ new Date()).toISOString(),
      last_modified: (/* @__PURE__ */ new Date()).toISOString(),
      tags: projectData.tags || [],
      documents: [],
      notes: [],
      bibliography: [],
      collaborators: [],
      progress: 0,
      metadata: {}
    };
    const updatedProjects = [...projects, newProject];
    saveProjects(updatedProjects);
    setCurrentProject(newProject);
    setIsCreatingProject(false);
    if (onProjectChange) {
      onProjectChange(newProject);
    }
  };
  const createNewNote = (noteData) => {
    if (!currentProject) return;
    const newNote = {
      id: `note_${Date.now()}`,
      title: noteData.title || "Nova Nota",
      content: noteData.content || "",
      document_id: noteData.document_id,
      document_section: noteData.document_section,
      tags: noteData.tags || [],
      created_date: (/* @__PURE__ */ new Date()).toISOString(),
      last_modified: (/* @__PURE__ */ new Date()).toISOString(),
      type: noteData.type || "general",
      importance: noteData.importance || "medium",
      highlights: []
    };
    const updatedProject = __spreadProps(__spreadValues({}, currentProject), {
      notes: [...currentProject.notes, newNote],
      last_modified: (/* @__PURE__ */ new Date()).toISOString()
    });
    const updatedProjects = projects.map((p) => p.id === currentProject.id ? updatedProject : p);
    saveProjects(updatedProjects);
    setCurrentProject(updatedProject);
    setIsCreatingNote(false);
  };
  const filteredNotes = (currentProject == null ? void 0 : currentProject.notes.filter((note) => {
    const matchesSearch = !searchQuery || note.title.toLowerCase().includes(searchQuery.toLowerCase()) || note.content.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesTags = filterTags.length === 0 || filterTags.some((tag) => note.tags.includes(tag));
    return matchesSearch && matchesTags;
  })) || [];
  const projectStats = currentProject ? {
    totalNotes: currentProject.notes.length,
    totalDocuments: currentProject.documents.length,
    bibliographyItems: currentProject.bibliography.length,
    completionPercentage: Math.round((currentProject.progress || 0) * 100),
    criticalNotes: currentProject.notes.filter((n) => n.importance === "critical").length,
    recentActivity: currentProject.notes.filter((n) => {
      const noteDate = new Date(n.last_modified);
      const weekAgo = /* @__PURE__ */ new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      return noteDate > weekAgo;
    }).length
  } : null;
  if (!currentProject && projects.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `research-workflow ${className}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "academic", className: "text-center py-12", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-2xl font-bold text-gray-700 mb-4", children: "Bem-vindo ao Fluxo de Pesquisa Acadêmica" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mb-6", children: "Organize sua pesquisa legislativa com ferramentas acadêmicas profissionais" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setIsCreatingProject(true),
            className: "glass-button-primary px-6 py-3 text-lg",
            children: "🚀 Criar Primeiro Projeto"
          }
        )
      ] }),
      isCreatingProject && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "academic", className: "w-full max-w-2xl mx-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-xl font-bold mb-4", children: "Novo Projeto de Pesquisa" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: (e) => {
          e.preventDefault();
          const formData = new FormData(e.target);
          createNewProject({
            title: formData.get("title"),
            description: formData.get("description"),
            tags: formData.get("tags").split(",").map((t) => t.trim()).filter(Boolean)
          });
        }, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Título do Projeto" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  name: "title",
                  type: "text",
                  required: true,
                  className: "glass-input",
                  placeholder: "Ex: Regulamentação do Transporte Urbano no Brasil"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Descrição" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "textarea",
                {
                  name: "description",
                  rows: 3,
                  className: "glass-input",
                  placeholder: "Descreva os objetivos e escopo da sua pesquisa..."
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Tags (separadas por vírgula)" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  name: "tags",
                  type: "text",
                  className: "glass-input",
                  placeholder: "transporte, regulamentação, urbano"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-3 mt-6", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "submit",
                className: "glass-button-primary flex-1",
                children: "Criar Projeto"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: () => setIsCreatingProject(false),
                className: "glass-button-secondary flex-1",
                children: "Cancelar"
              }
            )
          ] })
        ] })
      ] }) })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `research-workflow ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(GlassCard_default, { variant: "academic", className: "mb-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between items-start", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-bold text-gray-800", children: currentProject == null ? void 0 : currentProject.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                px-3 py-1 rounded-full text-sm font-medium
                ${(currentProject == null ? void 0 : currentProject.status) === "active" ? "bg-green-100 text-green-700" : (currentProject == null ? void 0 : currentProject.status) === "completed" ? "bg-blue-100 text-blue-700" : (currentProject == null ? void 0 : currentProject.status) === "planning" ? "bg-yellow-100 text-yellow-700" : "bg-gray-100 text-gray-700"}
              `, children: (currentProject == null ? void 0 : currentProject.status) === "active" ? "Ativo" : (currentProject == null ? void 0 : currentProject.status) === "completed" ? "Concluído" : (currentProject == null ? void 0 : currentProject.status) === "planning" ? "Planejamento" : "Arquivado" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mb-3", children: currentProject == null ? void 0 : currentProject.description }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 mb-3", children: currentProject == null ? void 0 : currentProject.tags.map((tag) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge text-sm", children: tag }, tag)) }),
        projectStats && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 md:grid-cols-4 gap-4 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-lg text-blue-600", children: projectStats.totalNotes }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Notas" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-lg text-green-600", children: projectStats.bibliographyItems }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Bibliografia" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "font-bold text-lg text-purple-600", children: [
              projectStats.completionPercentage,
              "%"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Progresso" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-bold text-lg text-orange-600", children: projectStats.recentActivity }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-gray-600", children: "Atividade 7d" })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2 ml-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setIsCreatingProject(true),
            className: "glass-button-secondary px-3 py-2 text-sm",
            children: "🔄 Trocar Projeto"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setIsCreatingNote(true),
            className: "glass-button-primary px-3 py-2 text-sm",
            children: "➕ Nova Nota"
          }
        )
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 mb-6", children: [
      { key: "overview", label: "📊 Visão Geral", icon: "📊" },
      { key: "documents", label: "📄 Documentos", icon: "📄" },
      { key: "notes", label: "📝 Notas", icon: "📝" },
      { key: "bibliography", label: "📚 Bibliografia", icon: "📚" },
      { key: "writing", label: "✍️ Redação", icon: "✍️" },
      { key: "collaboration", label: "👥 Colaboração", icon: "👥" }
    ].map((tab) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        onClick: () => setActiveTab(tab.key),
        className: `
              px-4 py-2 rounded-lg font-medium transition-all
              ${activeTab === tab.key ? "glass-card bg-blue-50 text-blue-700 border-blue-200" : "glass-button-secondary"}
            `,
        children: tab.label
      },
      tab.key
    )) }),
    activeTab === "overview" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "analysis", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-bold mb-4", children: "📈 Progresso do Projeto" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between text-sm mb-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Progresso Geral" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              projectStats == null ? void 0 : projectStats.completionPercentage,
              "%"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full bg-gray-200 rounded-full h-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            "div",
            {
              className: "bg-blue-600 h-2 rounded-full transition-all",
              style: { width: `${projectStats == null ? void 0 : projectStats.completionPercentage}%` }
            }
          ) })
        ] }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "research", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-bold mb-4", children: "⚡ Atividade Recente" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", children: currentProject == null ? void 0 : currentProject.notes.slice(0, 5).map((note) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 p-3 bg-gray-50 rounded", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                    w-2 h-2 rounded-full
                    ${note.importance === "critical" ? "bg-red-500" : note.importance === "high" ? "bg-orange-500" : note.importance === "medium" ? "bg-yellow-500" : "bg-green-500"}
                  ` }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium", children: note.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm text-gray-600", children: new Date(note.last_modified).toLocaleDateString("pt-BR") })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge text-xs", children: note.type })
        ] }, note.id)) })
      ] })
    ] }),
    activeTab === "notes" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "research", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col md:flex-row gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "text",
              value: searchQuery,
              onChange: (e) => setSearchQuery(e.target.value),
              placeholder: "Buscar nas notas...",
              className: "glass-input"
            }
          ) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => setShowAdvancedFilters(!showAdvancedFilters),
              className: "glass-button-secondary px-4 py-2",
              children: "🔍 Filtros"
            }
          )
        ] }),
        showAdvancedFilters && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 pt-4 border-t border-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Importância" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { className: "glass-input text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Todas" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "critical", children: "Crítica" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "high", children: "Alta" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "medium", children: "Média" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "low", children: "Baixa" })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Tipo" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { className: "glass-input text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Todos" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "general", children: "Geral" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "annotation", children: "Anotação" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "insight", children: "Insight" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "citation", children: "Citação" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "methodology", children: "Metodologia" })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Período" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { className: "glass-input text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Todo período" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "today", children: "Hoje" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "week", children: "Esta semana" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "month", children: "Este mês" })
            ] })
          ] })
        ] }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-4", children: filteredNotes.map((note) => /* @__PURE__ */ jsxRuntimeExports.jsx(GlassCard_default, { variant: "light", className: "hover:shadow-lg transition-shadow", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between items-start", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-bold text-lg", children: note.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                        w-3 h-3 rounded-full
                        ${note.importance === "critical" ? "bg-red-500" : note.importance === "high" ? "bg-orange-500" : note.importance === "medium" ? "bg-yellow-500" : "bg-green-500"}
                      ` })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-gray-600 mb-3 line-clamp-3", children: [
            note.content.substring(0, 200),
            "..."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
            note.tags.map((tag) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge text-xs", children: tag }, tag)),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge text-xs bg-blue-100 text-blue-700", children: note.type })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-gray-500", children: [
            "Modificado em ",
            new Date(note.last_modified).toLocaleDateString("pt-BR")
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2 ml-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => setSelectedNote(note),
              className: "glass-button-secondary px-3 py-1 text-sm",
              children: "📖 Ver"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "glass-button-secondary px-3 py-1 text-sm", children: "✏️ Editar" })
        ] })
      ] }) }, note.id)) })
    ] }),
    activeTab === "bibliography" && /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "academic", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-bold mb-4", children: "📚 Bibliografia do Projeto" }),
      (currentProject == null ? void 0 : currentProject.bibliography.length) === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-center py-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-gray-600 mb-4", children: "Nenhum item na bibliografia ainda" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-gray-500", children: "Use a pesquisa para adicionar documentos à sua bibliografia" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4", children: currentProject == null ? void 0 : currentProject.bibliography.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border border-gray-200 rounded-lg p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between items-start mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-bold", children: item.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                      px-2 py-1 rounded text-xs font-medium
                      ${item.importance === "primary" ? "bg-red-100 text-red-700" : item.importance === "secondary" ? "bg-yellow-100 text-yellow-700" : "bg-gray-100 text-gray-700"}
                    `, children: item.importance })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-gray-600 mb-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Fonte:" }),
            " ",
            item.source
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Data:" }),
            " ",
            item.date
          ] }),
          item.authors.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Autores:" }),
            " ",
            item.authors.join(", ")
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "ABNT:" }),
          " ",
          item.citation_abnt
        ] })
      ] }, item.id)) })
    ] }),
    isCreatingNote && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "academic", className: "w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-xl font-bold mb-4", children: "Nova Nota de Pesquisa" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        createNewNote({
          title: formData.get("title"),
          content: formData.get("content"),
          type: formData.get("type"),
          importance: formData.get("importance"),
          tags: formData.get("tags").split(",").map((t) => t.trim()).filter(Boolean)
        });
      }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Título da Nota" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  name: "title",
                  type: "text",
                  required: true,
                  className: "glass-input",
                  placeholder: "Ex: Análise do Art. 5º da Lei 12.587/2012"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Tipo de Nota" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { name: "type", className: "glass-input", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "general", children: "Geral" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "annotation", children: "Anotação" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "insight", children: "Insight" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "citation", children: "Citação" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "methodology", children: "Metodologia" })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Importância" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { name: "importance", className: "glass-input", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "low", children: "Baixa" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "medium", children: "Média" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "high", children: "Alta" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "critical", children: "Crítica" })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Tags (separadas por vírgula)" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  name: "tags",
                  type: "text",
                  className: "glass-input",
                  placeholder: "transporte, regulamentação, política"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "Conteúdo da Nota" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "textarea",
              {
                name: "content",
                rows: 10,
                required: true,
                className: "glass-input",
                placeholder: "Digite o conteúdo da sua nota de pesquisa..."
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-3 mt-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "submit",
              className: "glass-button-primary flex-1",
              children: "Criar Nota"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => setIsCreatingNote(false),
              className: "glass-button-secondary flex-1",
              children: "Cancelar"
            }
          )
        ] })
      ] })
    ] }) }),
    selectedNote && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(GlassCard_default, { variant: "academic", className: "w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between items-start mb-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-xl font-bold", children: selectedNote.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mt-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge", children: selectedNote.type }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `
                    px-2 py-1 rounded text-xs font-medium
                    ${selectedNote.importance === "critical" ? "bg-red-100 text-red-700" : selectedNote.importance === "high" ? "bg-orange-100 text-orange-700" : selectedNote.importance === "medium" ? "bg-yellow-100 text-yellow-700" : "bg-green-100 text-green-700"}
                  `, children: selectedNote.importance })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setSelectedNote(null),
            className: "glass-button-secondary px-3 py-2",
            children: "✕ Fechar"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "prose max-w-none", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "whitespace-pre-wrap bg-gray-50 p-4 rounded-lg", children: selectedNote.content }) }),
      selectedNote.tags.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 mt-4", children: selectedNote.tags.map((tag) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "glass-badge", children: tag }, tag)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-gray-500 mt-4", children: [
        "Criado em ",
        new Date(selectedNote.created_date).toLocaleDateString("pt-BR"),
        " • Modificado em ",
        new Date(selectedNote.last_modified).toLocaleDateString("pt-BR")
      ] })
    ] }) })
  ] });
};
var ResearchWorkflow_default = ResearchWorkflow;
export {
  ResearchWorkflow_default as default
};
