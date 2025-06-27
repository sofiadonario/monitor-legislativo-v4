import { j as jsxRuntimeExports, L as LoadingSpinner } from "./index-CREcncgK.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
import { a as apiClient_default } from "./Dashboard-BIcc2mI2.js";
import { a as API_ENDPOINTS } from "./api-CK1EtbNt.js";
import "./react-vendor-CSPBeBBz.js";
var __defProp$1 = Object.defineProperty;
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
class AIAgentsService {
  /**
   * Create a new AI agent
   */
  createAgent(config) {
    return __async$2(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.ai.agents, config);
    });
  }
  /**
   * Query an AI agent
   */
  queryAgent(agentId, request) {
    return __async$2(this, null, function* () {
      const endpoint = API_ENDPOINTS.ai.query.replace("{agent_id}", agentId);
      return apiClient_default.post(endpoint, request);
    });
  }
  /**
   * Get agent status
   */
  getAgentStatus(agentId) {
    return __async$2(this, null, function* () {
      const endpoint = API_ENDPOINTS.ai.status.replace("{agent_id}", agentId);
      return apiClient_default.get(endpoint);
    });
  }
  /**
   * Get system status
   */
  getSystemStatus() {
    return __async$2(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.ai.systemStatus);
    });
  }
  /**
   * Search agent memory
   */
  searchMemory(request) {
    return __async$2(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.ai.memorySearch, request);
    });
  }
  /**
   * Optimize agent memory
   */
  optimizeMemory(_0) {
    return __async$2(this, arguments, function* (agentId, options = {}) {
      return apiClient_default.post(API_ENDPOINTS.ai.memoryOptimize, __spreadValues$1({
        agent_id: agentId
      }, options));
    });
  }
  /**
   * Get memory performance stats
   */
  getMemoryPerformance(agentId) {
    return __async$2(this, null, function* () {
      const endpoint = API_ENDPOINTS.ai.memoryPerformance.replace("{agent_id}", agentId);
      return apiClient_default.get(endpoint);
    });
  }
  /**
   * Backup agent memory
   */
  backupMemory(agentId) {
    return __async$2(this, null, function* () {
      const endpoint = API_ENDPOINTS.ai.memoryBackup.replace("{agent_id}", agentId);
      return apiClient_default.post(endpoint, {});
    });
  }
  /**
   * Get available agent roles
   */
  getAvailableRoles() {
    return __async$2(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.ai.roles);
    });
  }
  /**
   * Check AI agents service health
   */
  checkHealth() {
    return __async$2(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.ai.health);
    });
  }
  /**
   * Helper method to create a research assistant agent
   */
  createResearchAssistant(agentId, budget = 10) {
    return __async$2(this, null, function* () {
      return this.createAgent({
        agent_id: agentId,
        role: "research_assistant",
        cost_budget_monthly: budget,
        temperature: 0.1,
        model: "gpt-4o-mini"
      });
    });
  }
  /**
   * Helper method to create a citation specialist agent
   */
  createCitationSpecialist(agentId, budget = 5) {
    return __async$2(this, null, function* () {
      return this.createAgent({
        agent_id: agentId,
        role: "citation_specialist",
        cost_budget_monthly: budget,
        temperature: 0.05,
        model: "gpt-4o-mini"
      });
    });
  }
  /**
   * Helper method for research queries
   */
  askResearchQuestion(agentId, question, context) {
    return __async$2(this, null, function* () {
      return this.queryAgent(agentId, {
        query: question,
        context,
        include_memory: true
      });
    });
  }
}
const aiAgentsService = new AIAgentsService();
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
class DocumentAnalysisService {
  /**
   * Perform comprehensive document analysis
   */
  analyzeDocument(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.analyze, request);
    });
  }
  /**
   * Generate document summary
   */
  summarizeDocument(documentData) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.summarize, documentData);
    });
  }
  /**
   * Extract enhanced metadata
   */
  extractMetadata(documentData) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.extractMetadata, documentData);
    });
  }
  /**
   * Analyze document content
   */
  analyzeContent(documentData) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.analyzeContent, documentData);
    });
  }
  /**
   * Discover document relationships
   */
  discoverRelationships(documentData) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.discoverRelationships, documentData);
    });
  }
  /**
   * Generate academic citation
   */
  generateCitation(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.generateCitation, request);
    });
  }
  /**
   * Generate multiple citations in batch
   */
  generateCitationsBatch(request) {
    return __async$1(this, null, function* () {
      return apiClient_default.post(API_ENDPOINTS.aiAnalysis.batchCitations, request);
    });
  }
  /**
   * Get supported citation styles
   */
  getCitationStyles() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.aiAnalysis.citationStyles);
    });
  }
  /**
   * Get analysis engine statistics
   */
  getAnalysisStatistics() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.aiAnalysis.analysisStatistics);
    });
  }
  /**
   * Get citation generator statistics
   */
  getCitationStatistics() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.aiAnalysis.citationStatistics);
    });
  }
  /**
   * Check AI document analysis service health
   */
  checkHealth() {
    return __async$1(this, null, function* () {
      return apiClient_default.get(API_ENDPOINTS.aiAnalysis.health);
    });
  }
  /**
   * Helper method to generate ABNT citation
   */
  generateABNTCitation(documentData, researchContext) {
    return __async$1(this, null, function* () {
      return this.generateCitation({
        document_data: documentData,
        citation_style: "abnt",
        include_url: true,
        include_access_date: true,
        academic_level: "graduate",
        research_context: researchContext
      });
    });
  }
  /**
   * Helper method to generate APA citation
   */
  generateAPACitation(documentData, researchContext) {
    return __async$1(this, null, function* () {
      return this.generateCitation({
        document_data: documentData,
        citation_style: "apa",
        include_url: true,
        include_access_date: true,
        academic_level: "graduate",
        research_context: researchContext
      });
    });
  }
  /**
   * Helper method for quick document analysis
   */
  quickAnalysis(documentData) {
    return __async$1(this, null, function* () {
      const [summary, metadata, citation] = yield Promise.all([
        this.summarizeDocument(documentData),
        this.extractMetadata(documentData),
        this.generateABNTCitation(documentData)
      ]);
      return { summary, metadata, citation };
    });
  }
  /**
   * Helper method for batch citation generation with different styles
   */
  generateMultiStyleCitations(documentData) {
    return __async$1(this, null, function* () {
      const styles = ["abnt", "apa", "chicago", "vancouver"];
      const requests = styles.map((style) => ({
        document_data: documentData,
        citation_style: style,
        include_url: true,
        include_access_date: true,
        academic_level: "graduate"
      }));
      const batchResult = yield this.generateCitationsBatch({ citations: requests });
      const result = {};
      batchResult.citations.forEach((citation, index) => {
        result[styles[index]] = citation;
      });
      return result;
    });
  }
}
const documentAnalysisService = new DocumentAnalysisService();
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
const AIResearchAssistant = ({
  selectedDocuments = [],
  onDocumentAnalyzed,
  className = ""
}) => {
  const [messages, setMessages] = reactExports.useState([]);
  const [inputMessage, setInputMessage] = reactExports.useState("");
  const [isLoading, setIsLoading] = reactExports.useState(false);
  const [agentStatus, setAgentStatus] = reactExports.useState(null);
  const [isAgentInitialized, setIsAgentInitialized] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [availableFeatures, setAvailableFeatures] = reactExports.useState([]);
  const messagesEndRef = reactExports.useRef(null);
  const agentId = "research_assistant_main";
  reactExports.useEffect(() => {
    initializeAgent();
    checkServiceHealth();
  }, []);
  reactExports.useEffect(() => {
    scrollToBottom();
  }, [messages]);
  const scrollToBottom = () => {
    var _a;
    (_a = messagesEndRef.current) == null ? void 0 : _a.scrollIntoView({ behavior: "smooth" });
  };
  const initializeAgent = () => __async(null, null, function* () {
    try {
      setIsLoading(true);
      try {
        const status = yield aiAgentsService.getAgentStatus(agentId);
        setAgentStatus(status);
        setIsAgentInitialized(true);
        addSystemMessage("AI Research Assistant connected successfully!");
      } catch (e) {
        yield aiAgentsService.createResearchAssistant(agentId, 15);
        const status = yield aiAgentsService.getAgentStatus(agentId);
        setAgentStatus(status);
        setIsAgentInitialized(true);
        addSystemMessage("New AI Research Assistant created and ready to help with Brazilian legislative research!");
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to initialize AI agent";
      setError(errorMessage);
      addSystemMessage(`Error: ${errorMessage}`, "error");
    } finally {
      setIsLoading(false);
    }
  });
  const checkServiceHealth = () => __async(null, null, function* () {
    try {
      const [aiHealth, analysisHealth] = yield Promise.all([
        aiAgentsService.checkHealth(),
        documentAnalysisService.checkHealth()
      ]);
      const features = [];
      if (aiHealth.ai_agents_available) features.push("AI Conversation");
      if (analysisHealth.ai_document_analysis_available) features.push("Document Analysis", "Citation Generation");
      setAvailableFeatures(features);
    } catch (err) {
      console.warn("Could not check service health:", err);
    }
  });
  const addSystemMessage = (content, type = "info") => {
    const message = {
      id: Date.now().toString(),
      type: "system",
      content,
      timestamp: /* @__PURE__ */ new Date()
    };
    setMessages((prev) => [...prev, message]);
  };
  const addUserMessage = (content) => {
    const message = {
      id: Date.now().toString(),
      type: "user",
      content,
      timestamp: /* @__PURE__ */ new Date()
    };
    setMessages((prev) => [...prev, message]);
  };
  const addAssistantMessage = (response, additionalData) => {
    const message = {
      id: Date.now().toString(),
      type: "assistant",
      content: response.response,
      timestamp: /* @__PURE__ */ new Date(),
      metadata: __spreadValues({
        cost_cents: response.cost_cents,
        from_cache: response.from_cache,
        processing_time_ms: response.response_time_ms
      }, additionalData)
    };
    setMessages((prev) => [...prev, message]);
  };
  const handleSendMessage = () => __async(null, null, function* () {
    if (!inputMessage.trim() || !isAgentInitialized || isLoading) return;
    const userMessage = inputMessage.trim();
    setInputMessage("");
    addUserMessage(userMessage);
    setIsLoading(true);
    setError(null);
    try {
      const context = {};
      if (selectedDocuments.length > 0) {
        context.selected_documents = selectedDocuments.map((doc) => ({
          urn: doc.urn,
          title: doc.title,
          type: doc.tipo_documento,
          authority: doc.autoridade
        }));
        context.document_count = selectedDocuments.length;
      }
      const response = yield aiAgentsService.askResearchQuestion(agentId, userMessage, context);
      const needsAnalysis = userMessage.toLowerCase().includes("analis") || userMessage.toLowerCase().includes("resumo") || userMessage.toLowerCase().includes("citação") || userMessage.toLowerCase().includes("citation");
      let additionalData = {};
      if (needsAnalysis && selectedDocuments.length > 0) {
        try {
          const analysisPromises = selectedDocuments.slice(0, 3).map((doc) => __async(null, null, function* () {
            const [summary, citation] = yield Promise.all([
              documentAnalysisService.summarizeDocument(doc),
              documentAnalysisService.generateABNTCitation(doc, userMessage)
            ]);
            return { summary, citation };
          }));
          const analyses = yield Promise.all(analysisPromises);
          additionalData.summaries = analyses.map((a) => a.summary);
          additionalData.citations = analyses.map((a) => a.citation);
          if (onDocumentAnalyzed) {
            analyses.forEach((analysis) => onDocumentAnalyzed(analysis));
          }
        } catch (analysisError) {
          console.warn("Document analysis failed:", analysisError);
        }
      }
      addAssistantMessage(response, additionalData);
      const updatedStatus = yield aiAgentsService.getAgentStatus(agentId);
      setAgentStatus(updatedStatus);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to send message";
      setError(errorMessage);
      addSystemMessage(`Error: ${errorMessage}`, "error");
    } finally {
      setIsLoading(false);
    }
  });
  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };
  const suggestedQuestions = [
    "Analise os documentos selecionados e identifique os principais temas de transporte.",
    "Gere citações ABNT para os documentos selecionados.",
    "Quais são as tendências regulatórias no transporte brasileiro?",
    "Compare a legislação federal e estadual de transporte.",
    "Identifique oportunidades de pesquisa nos documentos."
  ];
  const handleSuggestedQuestion = (question) => {
    setInputMessage(question);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `ai-research-assistant ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "assistant-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "header-info", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "🤖 AI Research Assistant" }),
        agentStatus && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "agent-status", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `status-indicator ${agentStatus.status}` }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("small", { children: [
            "Cost: ",
            (agentStatus.cost_summary.monthly_cost_cents / 100).toFixed(2),
            "¢ | Memory: ",
            agentStatus.memory_stats.short_term_entries + agentStatus.memory_stats.long_term_entries,
            " entries"
          ] })
        ] })
      ] }),
      availableFeatures.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "available-features", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("small", { children: [
        "Available: ",
        availableFeatures.join(", ")
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "messages-container", children: [
      messages.map((message) => {
        var _a, _b;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `message ${message.type}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "message-content", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "content-text", children: message.content }),
            message.metadata && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "message-metadata", children: [
              message.metadata.cost_cents !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cost", children: [
                "Cost: ",
                message.metadata.cost_cents.toFixed(4),
                "¢"
              ] }),
              message.metadata.from_cache && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cache-hit", children: "Cached" }),
              message.metadata.processing_time_ms && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "processing-time", children: [
                message.metadata.processing_time_ms.toFixed(0),
                "ms"
              ] })
            ] }),
            ((_a = message.metadata) == null ? void 0 : _a.citations) && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "citations-section", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Generated Citations:" }),
              message.metadata.citations.map((citation, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "citation-item", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "citation-text", children: citation.citation_text }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "citation-metadata", children: [
                  "Style: ",
                  citation.citation_style.toUpperCase(),
                  " | Quality: ",
                  (citation.quality_score * 100).toFixed(0),
                  "%"
                ] })
              ] }, index))
            ] }),
            ((_b = message.metadata) == null ? void 0 : _b.summaries) && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "summaries-section", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Document Summaries:" }),
              message.metadata.summaries.map((summary, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "summary-item", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h5", { children: summary.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: summary.summary_text }),
                summary.key_points.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "key-points", children: summary.key_points.map((point, pointIndex) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: point }, pointIndex)) })
              ] }, index))
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "message-timestamp", children: message.timestamp.toLocaleTimeString() })
        ] }, message.id);
      }),
      isLoading && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "message assistant loading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { size: "small" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "AI Research Assistant is thinking..." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: messagesEndRef })
    ] }),
    messages.length === 0 && selectedDocuments.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "suggested-questions", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: "Try asking:" }),
      suggestedQuestions.map((question, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          className: "suggested-question",
          onClick: () => handleSuggestedQuestion(question),
          disabled: isLoading || !isAgentInitialized,
          children: question
        },
        index
      ))
    ] }),
    selectedDocuments.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "context-info", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("small", { children: [
      "📄 ",
      selectedDocuments.length,
      " document",
      selectedDocuments.length !== 1 ? "s" : "",
      " selected for analysis"
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "input-container", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "textarea",
        {
          value: inputMessage,
          onChange: (e) => setInputMessage(e.target.value),
          onKeyPress: handleKeyPress,
          placeholder: isAgentInitialized ? "Ask me about Brazilian legislative research, document analysis, or citations..." : "Initializing AI Research Assistant...",
          disabled: isLoading || !isAgentInitialized,
          rows: 3,
          className: "message-input"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: handleSendMessage,
          disabled: isLoading || !isAgentInitialized || !inputMessage.trim(),
          className: "send-button",
          children: isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { size: "small" }) : "📤 Send"
        }
      )
    ] }),
    error && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "error-message", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Error:" }),
      " ",
      error,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => setError(null), className: "close-error", children: "×" })
    ] })
  ] });
};
var AIResearchAssistant_default = AIResearchAssistant;
export {
  AIResearchAssistant_default as default
};
