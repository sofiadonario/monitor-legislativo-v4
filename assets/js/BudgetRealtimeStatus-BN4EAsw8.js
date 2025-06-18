var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { j as jsxRuntimeExports } from "./index-CQfHVbgx.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
import { l as legislativeDataService } from "./Dashboard-g_mbnw4m.js";
import "./react-vendor-D_QSeeZk.js";
class BrowserEventEmitter {
  constructor() {
    __publicField(this, "events", /* @__PURE__ */ new Map());
  }
  on(event, listener) {
    if (!this.events.has(event)) {
      this.events.set(event, []);
    }
    this.events.get(event).push(listener);
    return this;
  }
  off(event, listener) {
    const listeners = this.events.get(event);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
      if (listeners.length === 0) {
        this.events.delete(event);
      }
    }
    return this;
  }
  emit(event, ...args) {
    const listeners = this.events.get(event);
    if (listeners && listeners.length > 0) {
      listeners.forEach((listener) => {
        try {
          listener(...args);
        } catch (error) {
          console.error(`Error in event listener for "${event}":`, error);
        }
      });
      return true;
    }
    return false;
  }
  removeAllListeners(event) {
    if (event) {
      this.events.delete(event);
    } else {
      this.events.clear();
    }
    return this;
  }
  listenerCount(event) {
    const listeners = this.events.get(event);
    return listeners ? listeners.length : 0;
  }
  eventNames() {
    return Array.from(this.events.keys());
  }
}
class BudgetRealtimeService extends BrowserEventEmitter {
  constructor() {
    super();
    __publicField(this, "pollingInterval", 6e4);
    // 1 minute - to stay within free tier limits
    __publicField(this, "pollingTimer");
    __publicField(this, "isPolling", false);
    __publicField(this, "lastCheckTimestamp");
    __publicField(this, "seenDocumentIds");
    __publicField(this, "storageKey", "monitor_legislativo_seen_docs");
    __publicField(this, "updateStorageKey", "monitor_legislativo_updates");
    this.lastCheckTimestamp = this.getLastCheckTimestamp();
    this.seenDocumentIds = this.loadSeenDocuments();
  }
  // Start polling for updates
  start() {
    if (this.isPolling) return;
    this.isPolling = true;
    this.emit("connected");
    this.checkForUpdates();
    this.pollingTimer = setInterval(() => {
      this.checkForUpdates();
    }, this.pollingInterval);
  }
  // Stop polling
  stop() {
    if (!this.isPolling) return;
    this.isPolling = false;
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = void 0;
    }
    this.emit("disconnected");
  }
  // Check for new documents
  async checkForUpdates() {
    try {
      const documents = await legislativeDataService.fetchDocuments({
        searchTerm: "",
        documentTypes: [],
        states: [],
        municipalities: [],
        keywords: [],
        dateFrom: new Date(this.lastCheckTimestamp),
        dateTo: /* @__PURE__ */ new Date()
      });
      const updates = [];
      const now = Date.now();
      documents.forEach((doc) => {
        if (!this.seenDocumentIds.has(doc.id)) {
          this.seenDocumentIds.add(doc.id);
          this.emit("new_document", doc);
          updates.push({
            documentId: doc.id,
            timestamp: now,
            type: "new"
          });
          const docDate = typeof doc.date === "string" ? new Date(doc.date) : doc.date;
          if (now - docDate.getTime() < 5 * 60 * 1e3) {
            this.showNotification("New Legislation", `${doc.type}: ${doc.title}`);
          }
        }
      });
      if (updates.length > 0) {
        this.saveUpdates(updates);
        this.saveSeenDocuments();
      }
      this.lastCheckTimestamp = now;
      this.saveLastCheckTimestamp();
      this.emit("status", {
        lastCheck: new Date(this.lastCheckTimestamp),
        documentsChecked: documents.length,
        newDocuments: updates.length
      });
    } catch (error) {
      console.error("Error checking for updates:", error);
      this.emit("error", error);
    }
  }
  // Show browser notification
  showNotification(title, body) {
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(title, {
        body,
        icon: "/favicon.ico",
        tag: "legislation-update",
        requireInteraction: false
      });
    }
  }
  // Load seen documents from localStorage
  loadSeenDocuments() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const data = JSON.parse(stored);
        const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1e3;
        const recentIds = Object.entries(data).filter(([_, timestamp]) => timestamp > thirtyDaysAgo).map(([id]) => id);
        return new Set(recentIds);
      }
    } catch (error) {
      console.error("Error loading seen documents:", error);
    }
    return /* @__PURE__ */ new Set();
  }
  // Save seen documents to localStorage
  saveSeenDocuments() {
    try {
      const data = {};
      const now = Date.now();
      this.seenDocumentIds.forEach((id) => {
        data[id] = now;
      });
      localStorage.setItem(this.storageKey, JSON.stringify(data));
    } catch (error) {
      console.error("Error saving seen documents:", error);
    }
  }
  // Get last check timestamp
  getLastCheckTimestamp() {
    try {
      const stored = localStorage.getItem("monitor_legislativo_last_check");
      if (stored) {
        return parseInt(stored, 10);
      }
    } catch (error) {
      console.error("Error loading last check timestamp:", error);
    }
    return Date.now() - 24 * 60 * 60 * 1e3;
  }
  // Save last check timestamp
  saveLastCheckTimestamp() {
    try {
      localStorage.setItem("monitor_legislativo_last_check", this.lastCheckTimestamp.toString());
    } catch (error) {
      console.error("Error saving last check timestamp:", error);
    }
  }
  // Save updates for cross-tab communication
  saveUpdates(updates) {
    try {
      const stored = localStorage.getItem(this.updateStorageKey);
      const existingUpdates = stored ? JSON.parse(stored) : [];
      const allUpdates = [...updates, ...existingUpdates].slice(0, 100);
      localStorage.setItem(this.updateStorageKey, JSON.stringify(allUpdates));
      window.dispatchEvent(new StorageEvent("storage", {
        key: this.updateStorageKey,
        newValue: JSON.stringify(allUpdates),
        url: window.location.href
      }));
    } catch (error) {
      console.error("Error saving updates:", error);
    }
  }
  // Listen for updates from other tabs
  startCrossTabSync() {
    window.addEventListener("storage", (e) => {
      if (e.key === this.updateStorageKey && e.newValue) {
        try {
          const updates = JSON.parse(e.newValue);
          updates.forEach((update) => {
            if (!this.seenDocumentIds.has(update.documentId)) {
              this.seenDocumentIds.add(update.documentId);
              this.emit("cross_tab_update", update);
            }
          });
        } catch (error) {
          console.error("Error processing cross-tab update:", error);
        }
      }
    });
  }
  // Get recent updates
  getRecentUpdates() {
    try {
      const stored = localStorage.getItem(this.updateStorageKey);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error("Error loading recent updates:", error);
    }
    return [];
  }
  // Clear all stored data
  clearStoredData() {
    localStorage.removeItem(this.storageKey);
    localStorage.removeItem(this.updateStorageKey);
    localStorage.removeItem("monitor_legislativo_last_check");
    this.seenDocumentIds.clear();
    this.lastCheckTimestamp = Date.now() - 24 * 60 * 60 * 1e3;
  }
  // Get polling status
  getStatus() {
    const nextCheck = new Date(this.lastCheckTimestamp + this.pollingInterval);
    return {
      isPolling: this.isPolling,
      lastCheck: new Date(this.lastCheckTimestamp),
      nextCheck: this.isPolling ? nextCheck : /* @__PURE__ */ new Date(),
      seenDocuments: this.seenDocumentIds.size
    };
  }
  // Request notification permission
  static async requestNotificationPermission() {
    if (!("Notification" in window)) {
      return false;
    }
    if (Notification.permission === "granted") {
      return true;
    }
    if (Notification.permission !== "denied") {
      const permission = await Notification.requestPermission();
      return permission === "granted";
    }
    return false;
  }
}
const budgetRealtimeService = new BudgetRealtimeService();
function useBudgetRealtime(options = {}) {
  const {
    autoStart = true,
    onNewDocument,
    onCrossTabUpdate
  } = options;
  const [status, setStatus] = reactExports.useState(budgetRealtimeService.getStatus());
  reactExports.useEffect(() => {
    const updateStatus = () => {
      setStatus(budgetRealtimeService.getStatus());
    };
    const interval = setInterval(updateStatus, 5e3);
    return () => clearInterval(interval);
  }, []);
  const handleNewDocument = reactExports.useCallback((document) => {
    onNewDocument == null ? void 0 : onNewDocument(document);
    setStatus(budgetRealtimeService.getStatus());
  }, [onNewDocument]);
  const handleCrossTabUpdate = reactExports.useCallback((update) => {
    onCrossTabUpdate == null ? void 0 : onCrossTabUpdate(update);
  }, [onCrossTabUpdate]);
  const handleStatusUpdate = reactExports.useCallback(() => {
    setStatus(budgetRealtimeService.getStatus());
  }, []);
  const start = reactExports.useCallback(() => {
    budgetRealtimeService.start();
    setStatus(budgetRealtimeService.getStatus());
  }, []);
  const stop = reactExports.useCallback(() => {
    budgetRealtimeService.stop();
    setStatus(budgetRealtimeService.getStatus());
  }, []);
  const requestNotifications = reactExports.useCallback(async () => {
    return await budgetRealtimeService.constructor.requestNotificationPermission();
  }, []);
  const clearHistory = reactExports.useCallback(() => {
    budgetRealtimeService.clearStoredData();
    setStatus(budgetRealtimeService.getStatus());
  }, []);
  reactExports.useEffect(() => {
    budgetRealtimeService.on("new_document", handleNewDocument);
    budgetRealtimeService.on("cross_tab_update", handleCrossTabUpdate);
    budgetRealtimeService.on("status", handleStatusUpdate);
    budgetRealtimeService.on("connected", handleStatusUpdate);
    budgetRealtimeService.on("disconnected", handleStatusUpdate);
    budgetRealtimeService.startCrossTabSync();
    if (autoStart && !status.isPolling) {
      start();
    }
    return () => {
      budgetRealtimeService.off("new_document", handleNewDocument);
      budgetRealtimeService.off("cross_tab_update", handleCrossTabUpdate);
      budgetRealtimeService.off("status", handleStatusUpdate);
      budgetRealtimeService.off("connected", handleStatusUpdate);
      budgetRealtimeService.off("disconnected", handleStatusUpdate);
      if (autoStart) {
        stop();
      }
    };
  }, [autoStart, handleNewDocument, handleCrossTabUpdate, handleStatusUpdate, start, stop, status.isPolling]);
  return {
    isPolling: status.isPolling,
    lastCheck: status.lastCheck,
    nextCheck: status.nextCheck,
    seenDocuments: status.seenDocuments,
    start,
    stop,
    requestNotifications,
    clearHistory
  };
}
const BudgetRealtimeStatus = () => {
  const [recentUpdates, setRecentUpdates] = reactExports.useState([]);
  const [showUpdates, setShowUpdates] = reactExports.useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = reactExports.useState(false);
  const [hasNewUpdates, setHasNewUpdates] = reactExports.useState(false);
  const {
    isPolling,
    lastCheck,
    nextCheck,
    seenDocuments,
    start,
    stop,
    requestNotifications,
    clearHistory
  } = useBudgetRealtime({
    onNewDocument: (document) => {
      const update = {
        id: `update-${Date.now()}-${document.id}`,
        document,
        timestamp: /* @__PURE__ */ new Date()
      };
      setRecentUpdates((prev) => [update, ...prev].slice(0, 20));
      setHasNewUpdates(true);
      setTimeout(() => {
        setRecentUpdates((prev) => prev.filter((u) => u.id !== update.id));
      }, 1e4);
    }
  });
  reactExports.useEffect(() => {
    if ("Notification" in window) {
      setNotificationsEnabled(Notification.permission === "granted");
    }
  }, []);
  const handleEnableNotifications = async () => {
    const granted = await requestNotifications();
    setNotificationsEnabled(granted);
  };
  const toggleUpdates = () => {
    setShowUpdates(!showUpdates);
    if (!showUpdates) {
      setHasNewUpdates(false);
    }
  };
  const formatTimeUntil = (date) => {
    const now = /* @__PURE__ */ new Date();
    const diff = date.getTime() - now.getTime();
    if (diff <= 0) return "Checking...";
    const seconds = Math.floor(diff / 1e3);
    const minutes = Math.floor(seconds / 60);
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };
  const formatRelativeTime = (date) => {
    const now = /* @__PURE__ */ new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 6e4);
    const hours = Math.floor(minutes / 60);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
  };
  reactExports.useEffect(() => {
    if (!isPolling) return;
    const timer = setInterval(() => {
      setShowUpdates((prev) => prev);
    }, 1e3);
    return () => clearInterval(timer);
  }, [isPolling]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "budget-realtime-container", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "realtime-status-bar", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "status-info", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `status-dot ${isPolling ? "active" : "inactive"}` }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "status-text", children: isPolling ? "Monitoring Active" : "Monitoring Paused" }),
        isPolling && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "next-check", children: [
          "Next check: ",
          formatTimeUntil(nextCheck)
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "status-actions", children: [
        hasNewUpdates && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "update-badge", children: recentUpdates.length }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: "status-button",
            onClick: toggleUpdates,
            "aria-label": "Toggle updates panel",
            children: "📊"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: "status-button",
            onClick: isPolling ? stop : start,
            "aria-label": isPolling ? "Pause monitoring" : "Start monitoring",
            children: isPolling ? "⏸️" : "▶️"
          }
        )
      ] })
    ] }),
    showUpdates && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "realtime-updates-panel", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "panel-header", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Legislative Updates" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "close-button", onClick: toggleUpdates, children: "×" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "panel-stats", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Last Check:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: formatRelativeTime(lastCheck) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: "Documents Tracked:" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-value", children: seenDocuments })
        ] })
      ] }),
      !notificationsEnabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "notification-prompt", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Enable notifications to get alerts for new legislation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: handleEnableNotifications, children: "Enable Notifications" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "updates-list", children: recentUpdates.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "no-updates", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No recent updates" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "subtitle", children: "New legislation will appear here" })
      ] }) : recentUpdates.map((update) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "update-item", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "update-icon", children: "📄" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "update-content", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { children: update.document.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "update-type", children: update.document.type }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("time", { children: formatRelativeTime(update.timestamp) })
        ] })
      ] }, update.id)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "panel-footer", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          className: "clear-button",
          onClick: () => {
            clearHistory();
            setRecentUpdates([]);
          },
          children: "Clear History"
        }
      ) })
    ] }),
    recentUpdates.length > 0 && !showUpdates && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "update-toast", onClick: toggleUpdates, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "toast-icon", children: "📄" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "toast-text", children: [
        recentUpdates[0].document.title.substring(0, 50),
        "..."
      ] })
    ] })
  ] });
};
export {
  BudgetRealtimeStatus
};
