import { j as jsxRuntimeExports } from "./index-CREcncgK.js";
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
var __objRest = (source, exclude) => {
  var target = {};
  for (var prop in source)
    if (__hasOwnProp.call(source, prop) && exclude.indexOf(prop) < 0)
      target[prop] = source[prop];
  if (source != null && __getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(source)) {
      if (exclude.indexOf(prop) < 0 && __propIsEnum.call(source, prop))
        target[prop] = source[prop];
    }
  return target;
};
const GlassCard = (_a) => {
  var _b = _a, {
    children,
    variant = "medium",
    size = "normal",
    interactive = false,
    className = "",
    animation = "none"
  } = _b, props = __objRest(_b, [
    "children",
    "variant",
    "size",
    "interactive",
    "className",
    "animation"
  ]);
  const getVariantClass = () => {
    switch (variant) {
      case "light":
        return "glass-light";
      case "heavy":
        return "glass-heavy";
      case "blue":
        return "glass-blue";
      case "green":
        return "glass-green";
      case "red":
        return "glass-red";
      case "purple":
        return "glass-purple";
      case "academic":
        return "glass-academic";
      case "research":
        return "glass-research";
      case "analysis":
        return "glass-analysis";
      default:
        return "glass-medium";
    }
  };
  const getSizeClass = () => {
    switch (size) {
      case "compact":
        return "glass-card-compact";
      case "large":
        return "glass-card-large";
      default:
        return "";
    }
  };
  const getAnimationClass = () => {
    switch (animation) {
      case "fade-in":
        return "glass-fade-in";
      case "slide-up":
        return "glass-slide-up";
      case "scale-in":
        return "glass-scale-in";
      default:
        return "";
    }
  };
  const classes = [
    "glass-card",
    getVariantClass(),
    getSizeClass(),
    interactive ? "glass-interactive" : "",
    getAnimationClass(),
    className
  ].filter(Boolean).join(" ");
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", __spreadProps(__spreadValues({ className: classes }, props), { children }));
};
var GlassCard_default = GlassCard;
export {
  GlassCard_default as G
};
