const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/js/Dashboard-Da8AjoJY.js","assets/js/leaflet-vendor-BcXhkSxI.js","assets/js/react-vendor-CSPBeBBz.js","assets/js/api-DW14Y_8v.js","assets/css/Dashboard-MxTedLtk.css","assets/js/LexMLSearchPage-D3x8nJUM.js"])))=>i.map(i=>d[i]);
import { r as requireReact, a as requireReactDom, g as getDefaultExportFromCjs } from "./react-vendor-CSPBeBBz.js";
import { r as reactExports } from "./leaflet-vendor-BcXhkSxI.js";
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
var hasRequiredReactJsxRuntime_production_min;
function requireReactJsxRuntime_production_min() {
  if (hasRequiredReactJsxRuntime_production_min) return reactJsxRuntime_production_min;
  hasRequiredReactJsxRuntime_production_min = 1;
  var f = /* @__PURE__ */ requireReact(), k = Symbol.for("react.element"), l = Symbol.for("react.fragment"), m = Object.prototype.hasOwnProperty, n = f.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner, p = { key: true, ref: true, __self: true, __source: true };
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
    jsxRuntime.exports = /* @__PURE__ */ requireReactJsxRuntime_production_min();
  }
  return jsxRuntime.exports;
}
var jsxRuntimeExports = /* @__PURE__ */ requireJsxRuntime();
var client = {};
var hasRequiredClient;
function requireClient() {
  if (hasRequiredClient) return client;
  hasRequiredClient = 1;
  var m = /* @__PURE__ */ requireReactDom();
  {
    client.createRoot = m.createRoot;
    client.hydrateRoot = m.hydrateRoot;
  }
  return client;
}
var clientExports = /* @__PURE__ */ requireClient();
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
var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, key + "", value);
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
const Dashboard = reactExports.lazy(() => __vitePreload(() => import("./Dashboard-Da8AjoJY.js").then((n) => n.D), true ? __vite__mapDeps([0,1,2,3,4]) : void 0));
const LexMLSearchPage = reactExports.lazy(() => __vitePreload(() => import("./LexMLSearchPage-D3x8nJUM.js"), true ? __vite__mapDeps([5,1,2,3]) : void 0));
const App = () => {
  const [currentPage, setCurrentPage] = reactExports.useState("dashboard");
  const renderCurrentPage = () => {
    switch (currentPage) {
      case "search":
        return /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading LexML Search..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(LexMLSearchPage, {}) });
      case "dashboard":
      default:
        return /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSpinner, { message: "Loading Dashboard..." }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(Dashboard, {}) });
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorBoundary, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "App", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "bg-white border-b border-gray-200 px-4 py-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-lg font-semibold text-gray-900", children: "Monitor Legislativo v4" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setCurrentPage("dashboard"),
            className: `px-3 py-1 text-sm rounded ${currentPage === "dashboard" ? "bg-blue-100 text-blue-700" : "text-gray-600 hover:text-gray-900"}`,
            children: "Dashboard"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setCurrentPage("search"),
            className: `px-3 py-1 text-sm rounded ${currentPage === "search" ? "bg-blue-100 text-blue-700" : "text-gray-600 hover:text-gray-900"}`,
            children: "LexML Search"
          }
        )
      ] })
    ] }) }),
    renderCurrentPage()
  ] }) });
};
var App_default = App;
const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}
const root = ReactDOM.createRoot(rootElement);
root.render(/* @__PURE__ */ jsxRuntimeExports.jsx(App_default, {}));
export {
  LoadingSpinner as L,
  __vitePreload as _,
  jsxRuntimeExports as j
};
