import { describe, expect, it } from "vitest";

import { analyzeParsedJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";

const SHIM = 'var Q=(e=>typeof require<"u"?require:e)(function(){});';
const CONSUMER = 'Q("electron").ipcRenderer.send("local");';

const ipcOf = (source: string, path = "bundle.js") => {
  const parsed = parseJavaScriptSource(source, path);
  expect(parsed).not.toBeNull();
  return analyzeParsedJavaScriptStaticSource(source, parsed!).electron.ipc;
};

describe("script require shim global binding identity", () => {
  it.each([
    "globalThis.Q=other;",
    "const target=globalThis;target.Q=other;",
    "const {globalThis:target}=globalThis;target.Q=other;",
    'Reflect.set(globalThis,"Q",other);',
    'Reflect.set({},"Q",other,globalThis);',
    'Object.defineProperty(globalThis,"Q",{value:other});',
    "Object.assign(globalThis,{Q:other});",
    "globalThis[key]=other;",
  ])("rejects the loader after a global property replacement: %s", (write) => {
    expect(ipcOf(`${SHIM}${write}${CONSUMER}`)).toEqual([]);
  });

  it.each([
    `"use strict";${SHIM}globalThis.Q=other;${CONSUMER}`,
    `{${SHIM}}globalThis.Q=other;${CONSUMER}`,
    `import type {X} from "types";${SHIM}globalThis.Q=other;${CONSUMER}`,
  ])(
    "keeps script storage despite syntax that does not isolate its vars: %s",
    (source) => {
      expect(ipcOf(source, "bundle.ts")).toEqual([]);
    },
  );

  it("rejects a loader replaced by indirect global eval", () => {
    expect(ipcOf(`${SHIM}(0,eval)("Q=other");${CONSUMER}`)).toEqual([]);
  });

  it.each([
    "{value:other,writable:false}",
    "{get(){return other},set(value){}}",
  ])(
    "does not let initialization erase an earlier global descriptor write: %s",
    (descriptor) => {
      expect(
        ipcOf(
          `Object.defineProperty(globalThis,"Q",${descriptor});${SHIM}${CONSUMER}`,
        ),
      ).toEqual([]);
    },
  );

  it.each([
    `${SHIM}${CONSUMER}globalThis.Q=other;`,
    `globalThis.Q=other;${SHIM}${CONSUMER}`,
    `${SHIM}globalThis.unrelated=other;${CONSUMER}`,
    `${SHIM}globalThis.Q.unrelated=other;${CONSUMER}`,
    `${SHIM}const target={};target.Q=other;${CONSUMER}`,
    `${SHIM}let target=globalThis;target={};target.Q=other;${CONSUMER}`,
    `${SHIM}const E=Q("electron");globalThis.Q=other;E.ipcRenderer.send("local");`,
  ])(
    "preserves a loader capture unaffected by a global property write: %s",
    (source) => {
      expect(ipcOf(source)).toMatchObject([{ channel: "local" }]);
    },
  );

  it.each(["let", "const"])(
    "preserves a top-level %s shim beside a global property replacement",
    (kind) => {
      expect(
        ipcOf(
          `${SHIM.replace("var Q", `${kind} Q`)}globalThis.Q=other;${CONSUMER}`,
        ),
      ).toMatchObject([{ channel: "local" }]);
    },
  );

  it.each(["bundle.cjs", "bundle.mjs", "bundle.cts", "bundle.mts"])(
    "preserves a module-local shim in %s beside a global replacement",
    (path) => {
      expect(
        ipcOf(`${SHIM}globalThis.Q=other;${CONSUMER}`, path),
      ).toMatchObject([{ channel: "local" }]);
    },
  );

  it.each([
    `export {};${SHIM}globalThis.Q=other;${CONSUMER}`,
    `(()=>{${SHIM}globalThis.Q=other;${CONSUMER}})();`,
    `function load(){${SHIM}globalThis.Q=other;${CONSUMER}}load();`,
  ])(
    "preserves a lexically isolated shim beside a global replacement: %s",
    (source) => {
      expect(ipcOf(source)).toMatchObject([{ channel: "local" }]);
    },
  );
});
