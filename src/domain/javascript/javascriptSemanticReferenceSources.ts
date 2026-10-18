import * as t from "@babel/types";
import {
  readExactJavaScriptLiteral,
  staticObjectProperty,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import type {
  JavaScriptSemanticAnalysisState,
  JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";
import {
  semanticArrayIndex,
  type JavaScriptSemanticPropertyPath as PropertyPath,
} from "./javascriptSemanticPropertyPaths.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import { evaluateSemanticExpression } from "./javascriptSemanticValues.js";
import { semanticSlotAtPath } from "./javascriptSemanticSlots.js";

interface ReferenceSource {
  readonly node: t.Node;
  readonly projection: PropertyPath;
}

/** Exclude references whose source slot or destructuring fallback is absent.
 * Before member effects exist, only inline syntax can prove a fallback unused;
 * named values must stay possible until their mutation facts are available. */
export const semanticReferenceSourcesInactive = (
  reference: {
    readonly requiredSources?: readonly ReferenceSource[];
    readonly fallbackSources?: readonly ReferenceSource[];
  },
  state: JavaScriptSemanticAnalysisState,
  mode: "effects" | "syntax-only" = "effects",
): boolean =>
  mode === "syntax-only"
    ? reference.fallbackSources?.some(syntaxReferenceSourceDefined) === true
    : reference.requiredSources?.some(
        (source) =>
          semanticSelectedReferenceSlot(source, state, source.node)
            ?.presence === "absent",
      ) === true ||
      reference.fallbackSources?.some((source) => {
        // Selection precedes effects through the chosen reference. A later escape
        // cannot make a fallback that was excluded at destructuring reachable.
        const slot = semanticSelectedReferenceSlot(source, state, source.node);
        return (
          slot?.presence === "present" &&
          (slot.value.status === "literal" ||
            slot.value.status === "union" ||
            slot.value.status === "object" ||
            slot.value.status === "array")
        );
      }) === true;

/** Reuse explicit-slot syntax without consulting potentially stale bindings. */
const syntaxReferenceSourceDefined = (source: ReferenceSource): boolean => {
  let node = unwrapJavaScriptExpression(source.node).node;
  for (const key of source.projection) {
    if (key === null || typeof key === "object") return false;
    if (t.isObjectExpression(node)) {
      const selected = staticObjectProperty(node, String(key));
      if (selected.status !== "explicit") return false;
      if (
        key === "__proto__" &&
        !selected.property.computed &&
        !selected.property.shorthand
      )
        return false;
      node = selected.property.value;
    } else if (t.isArrayExpression(node)) {
      if (node.elements.some(t.isSpreadElement)) return false;
      const index = semanticArrayIndex(key);
      const element = index === null ? undefined : node.elements[index];
      if (element == null) return false;
      node = element;
    } else return false;
    node = unwrapJavaScriptExpression(node).node;
  }
  return (
    readExactJavaScriptLiteral(node).found ||
    t.isObjectExpression(node) ||
    t.isArrayExpression(node)
  );
};

/** Select a retained source slot at its capture, before later effects. */
export const semanticSelectedReferenceSlot = (
  source: ReferenceSource,
  state: JavaScriptSemanticAnalysisState,
  capturePoint?: t.Node,
) => {
  const path: string[] = [];
  for (const key of source.projection) {
    if (key === null || typeof key === "object") return undefined;
    path.push(String(key));
  }
  return semanticSlotAtPath(
    evaluateSemanticExpression(source.node, state, capturePoint),
    path,
  );
};

/** Follow copied child references without equating a fresh rest copy with its source. */
export const semanticCopiedReferencePath = (
  initializer: JavaScriptSemanticBindingState["referenceInitializers"][number],
  path: PropertyPath,
  effect: "write" | "escape" | "reference",
): PropertyPath | null => {
  const offset = initializer.copyProjectionOffset;
  if (offset === undefined) return [...initializer.projection, ...path];
  const copiedPath = [...initializer.projection.slice(offset + 1), ...path];
  if (effect === "write" && copiedPath.length < 2) return null;
  if (effect === "reference" && copiedPath.length === 0) return null;
  let [key, ...remaining] = copiedPath;
  if (initializer.copyKind === "array-rest") {
    const startIndex = initializer.copyStartIndex ?? 0;
    if (key === undefined || key === null)
      key = { excludedKeys: [], startIndex };
    else if (typeof key === "object")
      key = {
        excludedKeys: key.excludedKeys.flatMap((name) => {
          const index = semanticArrayIndex(name);
          return index === null ? [] : [String(index + startIndex)];
        }),
        startIndex: (key.startIndex ?? 0) + startIndex,
      };
    else {
      const index = semanticArrayIndex(key);
      if (index === null) return null;
      key = index + startIndex;
    }
  } else {
    const excludedKeys = initializer.copyExcludedKeys ?? [];
    if (key === undefined || key === null) key = { excludedKeys };
    else if (typeof key === "object")
      key = {
        ...key,
        excludedKeys: [...new Set([...key.excludedKeys, ...excludedKeys])].sort(
          compareUnicodeCodePoints,
        ),
      };
    else if (excludedKeys.includes(String(key))) return null;
  }
  return [...initializer.projection.slice(0, offset), key, ...remaining];
};
