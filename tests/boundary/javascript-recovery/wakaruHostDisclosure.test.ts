import { expect, it } from "vitest";
import {
  recoveryLimitationsFor,
  wakaruHost,
} from "../../../src/javascript/recovery/WakaruRelease.js";

it("discloses the enforced ceiling on the verified host", () => {
  const [limitation] = recoveryLimitationsFor(wakaruHost("linux", "x64"));
  expect(limitation).toContain("linux-x64 (verified adapter)");
  expect(limitation).toContain("1 GiB address-space ceiling");
  expect(limitation).not.toContain("NOT enforced");
});

it("discloses that the ceiling is unenforced on an unverified host", () => {
  const [limitation] = recoveryLimitationsFor(wakaruHost("darwin", "arm64"));
  expect(limitation).toContain("darwin-arm64 (unverified host)");
  expect(limitation).toContain("NOT enforced");
  expect(limitation).toContain("util-linux --as");
});

it("marks only linux x64 as verified", () => {
  expect(wakaruHost("linux", "x64").verified).toBe(true);
  expect(wakaruHost("linux", "arm64").verified).toBe(false);
  expect(wakaruHost("darwin", "arm64").verified).toBe(false);
  expect(wakaruHost("win32", "x64").verified).toBe(false);
});
