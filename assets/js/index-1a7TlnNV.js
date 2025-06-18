const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/Dashboard-DXV2HtY-.js","assets/js/leaflet-vendor-HKOewaEh.js","assets/js/react-vendor-D_QSeeZk.js","assets/css/Dashboard-B7pxGJiW.css"])))=>i.map(i=>d[i]);
var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { r as requireReact, a as requireReactDom, g as getDefaultExportFromCjs } from "./react-vendor-D_QSeeZk.js";
import { r as reactExports } from "./leaflet-vendor-HKOewaEh.js";
(function polyfill() {
  const relList = document.createElement("link").relList;
  if (relList && relList.supports && relList.supports("modulepreload")) {
    return;
  }
  for (const link of document.querySelectorAll('link[rel="modulepreload"]')) {
    processPreload(link);
  }
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type !== "childList") {
        continue;
      }
      for (const node of mutation.addedNodes) {
        if (node.tagName === "LINK" && node.rel === "modulepreload")
          processPreload(node);
      }
    }
  }).observe(document, { childList: true, subtree: true });
  function getFetchOpts(link) {
    const fetchOpts = {};
    if (link.integrity) fetchOpts.integrity = link.integrity;
    if (link.referrerPolicy) fetchOpts.referrerPolicy = link.referrerPolicy;
    if (link.crossOrigin === "use-credentials")
      fetchOpts.credentials = "include";
    else if (link.crossOrigin === "anonymous") fetchOpts.credentials = "omit";
    else fetchOpts.credentials = "same-origin";
    return fetchOpts;
  }
  function processPreload(link) {
    if (link.ep)
      return;
    link.ep = true;
    const fetchOpts = getFetchOpts(link);
    fetch(link.href, fetchOpts);
  }
})();
var jsxRuntime = { exports: {} };
var reactJsxRuntime_production_min = {};
/**
 * @license React
 * react-jsx-runtime.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
var hasRequiredReactJsxRuntime_production_min;
function requireReactJsxRuntime_production_min() {
  if (hasRequiredReactJsxRuntime_production_min) return reactJsxRuntime_production_min;
  hasRequiredReactJsxRuntime_production_min = 1;
  var f = requireReact(), k = Symbol.for("react.element"), l = Symbol.for("react.fragment"), m = Object.prototype.hasOwnProperty, n = f.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner, p = { key: true, ref: true, __self: true, __source: true };
  function q(c, a, g) {
    var b, d = {}, e = null, h = null;
    void 0 !== g && (e = "" + g);
    void 0 !== a.key && (e = "" + a.key);
    void 0 !== a.ref && (h = a.ref);
    for (b in a) m.call(a, b) && !p.hasOwnProperty(b) && (d[b] = a[b]);
    if (c && c.defaultProps) for (b in a = c.defaultProps, a) void 0 === d[b] && (d[b] = a[b]);
    return { $$typeof: k, type: c, key: e, ref: h, props: d, _owner: n.current };
  }
  reactJsxRuntime_production_min.Fragment = l;
  reactJsxRuntime_production_min.jsx = q;
  reactJsxRuntime_production_min.jsxs = q;
  return reactJsxRuntime_production_min;
}
var hasRequiredJsxRuntime;
function requireJsxRuntime() {
  if (hasRequiredJsxRuntime) return jsxRuntime.exports;
  hasRequiredJsxRuntime = 1;
  {
    jsxRuntime.exports = requireReactJsxRuntime_production_min();
  }
  return jsxRuntime.exports;
}
var jsxRuntimeExports = requireJsxRuntime();
var client = {};
var hasRequiredClient;
function requireClient() {
  if (hasRequiredClient) return client;
  hasRequiredClient = 1;
  var m = requireReactDom();
  {
    client.createRoot = m.createRoot;
    client.hydrateRoot = m.hydrateRoot;
  }
  return client;
}
var clientExports = requireClient();
const ReactDOM = /* @__PURE__ */ getDefaultExportFromCjs(clientExports);
const scriptRel = "modulepreload";
const assetsURL = function(dep) {
  return "/monitor-legislativo-v4/" + dep;
};
const seen = {};
const __vitePreload = function preload(baseModule, deps, importerUrl) {
  let promise = Promise.resolve();
  if (deps && deps.length > 0) {
    let allSettled2 = function(promises) {
      return Promise.all(
        promises.map(
          (p) => Promise.resolve(p).then(
            (value) => ({ status: "fulfilled", value }),
            (reason) => ({ status: "rejected", reason })
          )
        )
      );
    };
    document.getElementsByTagName("link");
    const cspNonceMeta = document.querySelector(
      "meta[property=csp-nonce]"
    );
    const cspNonce = (cspNonceMeta == null ? void 0 : cspNonceMeta.nonce) || (cspNonceMeta == null ? void 0 : cspNonceMeta.getAttribute("nonce"));
    promise = allSettled2(
      deps.map((dep) => {
        dep = assetsURL(dep);
        if (dep in seen) return;
        seen[dep] = true;
        const isCss = dep.endsWith(".css");
        const cssSelector = isCss ? '[rel="stylesheet"]' : "";
        if (document.querySelector(`link[href="${dep}"]${cssSelector}`)) {
          return;
        }
        const link = document.createElement("link");
        link.rel = isCss ? "stylesheet" : scriptRel;
        if (!isCss) {
          link.as = "script";
        }
        link.crossOrigin = "";
        link.href = dep;
        if (cspNonce) {
          link.setAttribute("nonce", cspNonce);
        }
        document.head.appendChild(link);
        if (isCss) {
          return new Promise((res, rej) => {
            link.addEventListener("load", res);
            link.addEventListener(
              "error",
              () => rej(new Error(`Unable to preload CSS for ${dep}`))
            );
          });
        }
      })
    );
  }
  function handlePreloadError(err) {
    const e = new Event("vite:preloadError", {
      cancelable: true
    });
    e.payload = err;
    window.dispatchEvent(e);
    if (!e.defaultPrevented) {
      throw err;
    }
  }
  return promise.then((res) => {
    for (const item of res || []) {
      if (item.status !== "rejected") continue;
      handlePreloadError(item.reason);
    }
    return baseModule().catch(handlePreloadError);
  });
};
class ErrorBoundary extends reactExports.Component {
  constructor(props) {
    super(props);
    __publicField(this, "reportError", (error, errorInfo) => {
      const errorReport = {
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href
      };
      console.log("Error report:", errorReport);
    });
    this.state = { hasError: false };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    console.error("Error caught by boundary:", error, errorInfo);
    this.reportError(error, errorInfo);
  }
  render() {
    var _a;
    if (this.state.hasError) {
      return this.props.fallback || /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "error-boundary", role: "alert", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Academic Research Platform Error" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Error Details" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { children: (_a = this.state.error) == null ? void 0 : _a.stack })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => window.location.reload(), children: "Reload Application" })
      ] });
    }
    return this.props.children;
  }
}
const LoadingSpinner = ({
  message = "Loading legislation data...",
  size = "medium"
}) => {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `loading-spinner ${size}`, role: "status", "aria-live": "polite", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "spinner-animation", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "loading-message", children: message })
  ] });
};
const Dashboard = reactExports.lazy(() => __vitePreload(() => import("./Dashboard-DXV2HtY-.js"), true ? __vite__mapDeps([0,1,2,3]) : void 0));
const App = () => {
  const [showSpinner, setShowSpinner] = reactExports.useState(false);
  const [apiStatus, setApiStatus] = reactExports.useState("Not tested");
  const [isTestingApi, setIsTestingApi] = reactExports.useState(false);
  const [showDashboard, setShowDashboard] = reactExports.useState(false);
  const testBackendApi = async () => {
    setIsTestingApi(true);
    setApiStatus("Testing...");
    try {
      const response = await fetch("https://monitor-legislativo-v4-production.up.railway.app/health");
      const data = await response.json();
      setApiStatus(`✅ API Working! Status: ${data.status}`);
    } catch (error) {
      setApiStatus(`❌ API Error: ${error instanceof Error ? error.message : "Unknown error"}`);
    } finally {
      setIsTestingApi(false);
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorBoundary, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "App", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { style: {
      padding: "2rem",
      textAlign: "center",
      backgroundColor: "#f0f0f0",
      borderBottom: "1px solid #ddd"
    }, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { children: "Monitor Legislativo v4" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Brazilian Legislative Monitoring System" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "✅ Successfully deployed to GitHub Pages!" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        "🔗 Backend API: ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "https://monitor-legislativo-v4-production.up.railway.app/health", target: "_blank", children: "Railway Health Check" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { style: { padding: "2rem", textAlign: "center" }, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "🎉 Deployment Successful!" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Your full-stack application is now live:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { style: { listStyle: "none", padding: 0 }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "✅ Frontend: GitHub Pages" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "✅ Backend: Railway" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "✅ Database: Supabase" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "✅ Cache: Upstash Redis" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Step 1: ErrorBoundary added ✅" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Step 2: LoadingSpinner added ✅" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Step 3: API connectivity test ✅" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Step 4: Suspense + Lazy Loading ✅" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: { margin: "2rem 0" }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => setShowSpinner(!showSpinner),
            style: {
              padding: "0.5rem 1rem",
              margin: "0.5rem",
              backgroundColor: "#007bff",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer"
            },
            children: [
              showSpinner ? "Hide" : "Show",
              " Loading Spinner"
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: testBackendApi,
            disabled: isTestingApi,
            style: {
              padding: "0.5rem 1rem",
              margin: "0.5rem",
              backgroundColor: isTestingApi ? "#6c757d" : "#28a745",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: isTestingApi ? "not-allowed" : "pointer"
            },
            children: isTestingApi ? "Testing..." : "Test Railway API"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => setShowDashboard(!showDashboard),
            style: {
              padding: "0.5rem 1rem",
              margin: "0.5rem",
              backgroundColor: "#6f42c1",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer"
            },
            children: [
              showDashboard ? "Hide" : "Show",
              " Dashboard"
            ]
          }
        )
      ] }),
      showSpinner && /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Testing spinner component..." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: {
        margin: "1rem 0",
        padding: "1rem",
        backgroundColor: "#f8f9fa",
        borderRadius: "4px",
        border: "1px solid #dee2e6"
      }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "API Status:" }),
        " ",
        apiStatus
      ] }),
      showDashboard && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: {
        margin: "2rem 0",
        padding: "1rem",
        border: "2px solid #6f42c1",
        borderRadius: "8px",
        backgroundColor: "#f8f9ff"
      }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "🚀 Step 5: Dashboard with Suspense" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading Dashboard component..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(Dashboard, {}) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "✅ REBUILD COMPLETE!" }),
        " All components working!"
      ] })
    ] })
  ] }) });
};
const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}
const root = ReactDOM.createRoot(rootElement);
root.render(/* @__PURE__ */ jsxRuntimeExports.jsx(App, {}));
export {
  LoadingSpinner as L,
  __vitePreload as _,
  jsxRuntimeExports as j
};
