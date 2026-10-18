import { isAbsolute } from "node:path";
import { expect, it } from "vitest";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { err } from "../../domain/result.js";
import { PacketCaptureService } from "./PacketCaptureService.js";

const absolute = (name: string): string =>
  process.platform === "win32" ? `C:\\captures\\${name}` : `/captures/${name}`;

const recordingService = () => {
  const inputs: unknown[] = [];
  const service = new PacketCaptureService({
    inspect: async (input) => {
      inputs.push(input);
      return err(new AnalysisCancelledError("inspect_packet_capture"));
    },
    inspectFields: async () => {
      throw new Error("Unexpected field discovery call");
    },
    close: async () => {},
  });
  return { service, inputs };
};

it("rejects a relative TLS key log before provider work", async () => {
  const { service, inputs } = recordingService();
  for (const tls_key_log_path of ["client.keys", "", "a\0b"]) {
    const result = await service.inspect({
      path: absolute("a.pcapng"),
      fields: ["http2.headers.path"],
      tls_key_log_path,
    });
    if (result.ok) throw new Error("Expected key-log input refusal");
    expect(result.error).toMatchObject({
      _tag: "AnalysisInputError",
      issues: [expect.objectContaining({ path: ["tls_key_log_path"] })],
    });
  }
  expect(inputs).toEqual([]);
});

it("passes an absolute key log to the provider and omits it when not selected", async () => {
  const { service, inputs } = recordingService();
  const keyLog = absolute("client.keys");
  expect(isAbsolute(keyLog)).toBe(true);
  await service.inspect({
    path: absolute("a.pcapng"),
    fields: ["http2.headers.path"],
    tls_key_log_path: keyLog,
  });
  await service.inspect({
    path: absolute("a.pcapng"),
    fields: ["http2.headers.path"],
  });
  // An in-process caller's explicit undefined is normalized to absence.
  await service.inspect({
    path: absolute("a.pcapng"),
    fields: ["http2.headers.path"],
    tls_key_log_path: undefined,
  });
  expect(inputs).toEqual([
    expect.objectContaining({ tls_key_log_path: keyLog }),
    expect.not.objectContaining({ tls_key_log_path: expect.anything() }),
    expect.not.objectContaining({ tls_key_log_path: expect.anything() }),
  ]);
  expect(Object.keys(inputs[1] ?? {})).not.toContain("tls_key_log_path");
  expect(Object.keys(inputs[2] ?? {})).not.toContain("tls_key_log_path");
});

it("refuses display filters that could probe redacted credentials when a key log is selected", async () => {
  const { service, inputs } = recordingService();
  const base = {
    path: absolute("a.pcapng"),
    fields: ["http2.headers.path"],
  };
  for (const display_filter of [
    'http.cookie contains "sess=a"',
    'HTTP2.HEADERS.AUTHORIZATION matches "^Bearer"',
    'http3.headers.set_cookie == "x" || tcp',
    'frame contains "http.authorization"',
  ]) {
    const result = await service.inspect({
      ...base,
      display_filter,
      tls_key_log_path: absolute("client.keys"),
    });
    if (result.ok) throw new Error("Expected credential filter refusal");
    expect(result.error).toMatchObject({
      _tag: "AnalysisInputError",
      issues: [expect.objectContaining({ path: ["display_filter"] })],
    });
  }
  expect(inputs).toEqual([]);
  await service.inspect({
    ...base,
    display_filter: 'http.cookie contains "sess=a"',
  });
  await service.inspect({
    ...base,
    display_filter: "http2.headers.path",
    tls_key_log_path: absolute("client.keys"),
  });
  expect(inputs).toHaveLength(2);
});
