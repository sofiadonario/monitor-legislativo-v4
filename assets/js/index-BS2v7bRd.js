var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { r as requireReact, a as requireReactDom, g as getDefaultExportFromCjs } from "./react-vendor-D_QSeeZk.js";
import { r as reactExports } from "./leaflet-vendor-CapjgQv2.js";
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
const App = () => {
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Next: Adding components gradually..." })
    ] })
  ] }) });
};
const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}
const root = ReactDOM.createRoot(rootElement);
root.render(/* @__PURE__ */ jsxRuntimeExports.jsx(App, {}));
