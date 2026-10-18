import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { inspect } from "node:util";
import { expect, it, onTestFinished } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { PacketCaptureService } from "../../../src/application/captures/PacketCaptureService.js";
import { readStableArtifact } from "../../../src/artifacts/readStableArtifact.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { OwnedCommandFailure } from "../../../src/process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { TsharkCaptureProvider } from "../../../src/captures/TsharkCaptureProvider.js";

const completedProcess = (text: string, stderr = "", processError?: Error) => {
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null as number | null,
    signalCode: null,
    kill: () => true,
  });
  setImmediate(() => {
    child.stdout.end(text);
    child.stderr.end(stderr);
    if (processError !== undefined) child.emit("error", processError);
    child.exitCode = 0;
    child.emit("exit", 0, null);
    child.emit("close", 0, null);
  });
  return child;
};

// Exercise the real adapter and failure projection with an injected command
// outcome. No native process or installed TShark is required for this boundary.
const inspectFailure = async (
  failure:
    | OwnedCommandFailure
    | {
        stdout: string;
        stderr: string;
        processError?: Error;
        failCleanup?: boolean;
      },
) => {
  const directory = await createTestTempDirectory("rea-tls-command-failure-");
  const tool = join(directory, "producer");
  const path = join(directory, "capture.pcap");
  const keyLog = join(directory, "keys.log");
  await writeFile(tool, "fixture executable identity", { mode: 0o700 });
  await writeFile(path, "fixture capture");
  await writeFile(keyLog, "# fixture key log\n");
  let privateKeyLog: string | undefined;
  let allowCleanup = false;
  const provider = new TsharkCaptureProvider(
    { REA_TSHARK_COMMAND: tool, REA_TSHARK_PRLIMIT_COMMAND: tool },
    async (input) => {
      if (!input.arguments.includes("--version")) {
        privateKeyLog = input.arguments
          .find((argument) => argument.startsWith("tls.keylog_file:"))
          ?.slice("tls.keylog_file:".length);
        expect(privateKeyLog).toBeDefined();
        expect(existsSync(privateKeyLog!)).toBe(true);
        if (failure instanceof OwnedCommandFailure) throw failure;
      }
      return {
        process:
          input.arguments.includes("--version") ||
          failure instanceof OwnedCommandFailure
            ? completedProcess("TShark (Wireshark) 4.6.9 (fixture)\n")
            : completedProcess(
                failure.stdout,
                failure.stderr,
                failure.processError,
              ),
        ownership: {
          runId: input.runId,
          leaderPid: 41234,
          processGroupId: 41234,
        },
        cleanup: async () =>
          !input.arguments.includes("--version") &&
          !(failure instanceof OwnedCommandFailure) &&
          failure.failCleanup &&
          !allowCleanup
            ? { cleaned: false, reason: "fixture process cleanup blocked" }
            : { cleaned: true, signaled: false },
      };
    },
    () => PrivateRuntimeRoot.create({ parent: directory, prefix: "decoder-" }),
    "linux",
    readStableArtifact,
    async (limits) => limits,
  );
  onTestFinished(async () => {
    allowCleanup = true;
    await provider.close();
  });
  const result = await new PacketCaptureService(provider).inspect({
    path,
    fields: ["http.request.uri"],
    tls_key_log_path: keyLog,
  });
  if (result.ok) throw new Error("Expected injected command failure");
  expect(privateKeyLog).toBeDefined();
  expect(existsSync(privateKeyLog!)).toBe(false);
  const observed =
    failure instanceof OwnedCommandFailure
      ? failure.snapshot
      : {
          stdout: { observedBytes: Buffer.byteLength(failure.stdout) },
          stderr: { observedBytes: Buffer.byteLength(failure.stderr) },
        };
  if (observed === null) expect(result.error.capturedOutput).toBeUndefined();
  else
    expect(result.error.capturedOutput).toMatchObject({
      stdout: "",
      stderr: "",
      stdout_bytes: observed.stdout.observedBytes,
      stderr_bytes: observed.stderr.observedBytes,
    });
  expect(JSON.stringify(projectAnalysisError(result.error))).not.toContain(
    "fixture-credential",
  );
  return {
    error: result.error,
    retry: async () => {
      allowCleanup = true;
      await provider.close();
    },
  };
};

const snapshot = {
  stdout: { text: "fixture-credential", bytes: 18, observedBytes: 5000 },
  stderr: { text: "fixture-secret-17", bytes: 17, observedBytes: 17 },
  exitCode: null,
  signal: null,
};

it.each(["opaque reason", { request: "cancel decrypting command" }])(
  "preserves the owner's exact cancellation reason while withholding output: %j",
  async (reason) => {
    const { error } = await inspectFailure(
      new OwnedCommandFailure(
        "cancelled",
        "Command cancelled.",
        snapshot,
        null,
        {
          cancellation: { reason },
        },
      ),
    );
    expect(error._tag).toBe("AnalysisCancelledError");
    expect(error.cause).toBe(reason);
  },
);

it("preserves the physical process error while withholding decrypted output", async () => {
  const processError = Object.assign(new Error("fixture stream read failure"), {
    code: "EIO",
  });
  const { error } = await inspectFailure(
    new OwnedCommandFailure(
      "process",
      "Output collection failed.",
      snapshot,
      null,
      {
        processError,
        collectionFailure: true,
      },
    ),
  );
  expect(error._tag).toBe("AnalysisOutputError");
  expect(error.cause).toBeInstanceOf(OwnedCommandFailure);
  expect(error.cause).toMatchObject({ processError, collectionFailure: true });
  expect((error.cause as OwnedCommandFailure).processError).toBe(processError);
});

it.each(["collection", "output-limit", "cleanup"] as const)(
  "withholds nested snapshots from real command %s failures",
  async (failure) => {
    const processError = new Error("fixture physical stream failure");
    const { error, retry } = await inspectFailure({
      stdout:
        "fixture-credential" +
        (failure === "output-limit" ? "x".repeat(4 * 1024 * 1024) : ""),
      stderr: "fixture-cookie",
      ...(failure === "output-limit" ? {} : { processError }),
      failCleanup: failure === "cleanup",
    });
    const primary = error.cleanupPrimary ?? error;
    expect(primary._tag).toBe(
      failure === "output-limit"
        ? "AnalysisResourceConstraintError"
        : "AnalysisOutputError",
    );
    expect(primary.cause).toBeInstanceOf(OwnedCommandFailure);
    const command = primary.cause as OwnedCommandFailure;
    if (failure !== "output-limit") {
      expect(command.processError).toBe(processError);
      expect(command.collectionFailure).toBe(true);
    }
    if (failure === "cleanup") {
      expect(error.cleanupIncomplete).toBe(true);
      expect(error.cleanupResources).toEqual(
        expect.arrayContaining(["pid:41234", "process-group:41234"]),
      );
      // A returned supervisor exposes its private output via snapshot(), even
      // though util.inspect cannot see those private buffers.
      expect(command.cleanupOwner === undefined).toBe(true);
      await retry();
      expect(error.cleanupIncomplete).toBe(false);
      expect(error.cleanupResources).toEqual([]);
    }
    // Error.cause is non-enumerable and omitted by JSON.stringify. Inspect the
    // actual returned error, including all nested command wrappers.
    const diagnostic = inspect(error, { depth: null, maxStringLength: null });
    expect(diagnostic.includes("fixture-credential")).toBe(false);
    expect(diagnostic.includes("fixture-cookie")).toBe(false);
  },
);

it("withholds nested command output when the outer failure has no snapshot", async () => {
  const { error } = await inspectFailure(
    new OwnedCommandFailure(
      "timeout",
      "Command deadline elapsed.",
      null,
      null,
      {
        cause: new OwnedCommandFailure(
          "timeout",
          "Command deadline elapsed.",
          snapshot,
        ),
      },
    ),
  );
  expect(error._tag).toBe("AnalysisTimeoutError");
  expect(inspect(error, { depth: null }).includes("fixture-credential")).toBe(
    false,
  );
});

const completedInspection = async (options: {
  cancelIntegrity?: boolean;
  malformed?: boolean;
  failUnlink?: boolean;
  failClose?: boolean;
  cancelClose?: boolean;
}) => {
  const directory = await createTestTempDirectory("rea-tls-finalization-");
  const tool = join(directory, "producer");
  const path = join(directory, "capture.pcap");
  const keyLog = join(directory, "keys.log");
  await writeFile(tool, "fixture executable identity", { mode: 0o700 });
  await writeFile(path, "fixture capture");
  await writeFile(keyLog, "# fixture key log\n");
  const controller = new AbortController();
  const reason = { request: "cancel during finalization" };
  let allowClose = !options.failClose;
  let privateKeyLog: string | undefined;
  const fields = {
    "frame.number": ["1"],
    "http.request.uri": ["/items"],
    "http.authorization": ["fixture-credential"],
  };
  const provider = new TsharkCaptureProvider(
    { REA_TSHARK_COMMAND: tool, REA_TSHARK_PRLIMIT_COMMAND: tool },
    async (input) => ({
      process: completedProcess(
        input.arguments.includes("--version")
          ? "TShark (Wireshark) 4.6.9 (fixture)\n"
          : options.malformed
            ? "invalid fixture-credential JSON"
            : JSON.stringify([{ _source: { layers: fields } }]),
      ),
      ownership: {
        runId: input.runId,
        leaderPid: 41235,
        processGroupId: 41235,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    }),
    async () => {
      const root = await PrivateRuntimeRoot.create({
        parent: directory,
        prefix: "decoder-",
      });
      privateKeyLog = join(root.path, "tls-key-log");
      return {
        path: root.path,
        close: async () => {
          if (options.cancelClose) controller.abort(reason);
          if (!allowClose) throw new Error("fixture workspace cleanup failure");
          await root.close();
        },
      };
    },
    "linux",
    async (...args) => {
      if (args[0] === privateKeyLog && options.cancelIntegrity)
        controller.abort(reason);
      const read = await readStableArtifact(...args);
      if (args[0] === privateKeyLog && options.failUnlink) {
        // A directory cannot be unlinked by rm without recursive, including as
        // root. The exact workspace owner can still remove it on close/retry.
        await rm(args[0]);
        await mkdir(args[0]);
      }
      return read;
    },
    async (limits) => limits,
  );
  onTestFinished(async () => {
    allowClose = true;
    await provider.close();
  });
  const result = await new PacketCaptureService(provider).inspect(
    {
      path,
      fields: ["http.request.uri", "http.authorization"],
      tls_key_log_path: keyLog,
    },
    { signal: controller.signal },
  );
  expect(privateKeyLog).toBeDefined();
  return {
    result,
    reason,
    privateKeyLog: privateKeyLog!,
    retry: async () => {
      allowClose = true;
      await provider.close();
    },
  };
};

it.each([false, true])(
  "retains completed output through key-log integrity cancellation (malformed=%s)",
  async (malformed) => {
    const f = await completedInspection({ cancelIntegrity: true, malformed });
    if (f.result.ok)
      throw new Error("Expected cancellation or malformed output");
    expect(f.result.error._tag).toBe(
      malformed ? "AnalysisOutputError" : "AnalysisCancelledError",
    );
    if (!malformed) {
      expect(f.result.error.cause).toBe(f.reason);
      expect(f.result.error.partialObservation).toMatchObject({
        normalized_result: {
          packets: [{ "frame.number": ["1"], "http.request.uri": ["/items"] }],
          redactions: [
            {
              frame: "1",
              field: "http.authorization",
              reason: "transport-credential",
            },
          ],
        },
      });
    }
    expect(JSON.stringify(projectAnalysisError(f.result.error))).not.toContain(
      "fixture-credential",
    );
    expect(existsSync(f.privateKeyLog)).toBe(false);
  },
);

it.each(
  [false, true].flatMap((failClose) =>
    [false, true].map((cancelClose) => ({ failClose, cancelClose })),
  ),
)(
  "ties failed key-log unlink to actual workspace recovery: %j",
  async ({ failClose, cancelClose }) => {
    const f = await completedInspection({
      failUnlink: true,
      failClose,
      cancelClose,
    });
    if (!failClose && !cancelClose) {
      if (!f.result.ok) throw f.result.error;
      expect(f.result.value.normalized_result).toMatchObject({
        packets: [{ "http.request.uri": ["/items"] }],
      });
    } else {
      if (f.result.ok)
        throw new Error("Expected cleanup failure or cancellation");
      const error = f.result.error;
      expect(error.cleanupIncomplete).toBe(failClose);
      expect(error.partialObservation).toMatchObject({
        normalized_result: {
          packets: [{ "http.request.uri": ["/items"] }],
        },
      });
      if (cancelClose) {
        const primary = failClose ? error.cleanupPrimary : error;
        expect(primary?._tag).toBe("AnalysisCancelledError");
        expect(primary?.cause).toBe(f.reason);
      }
      expect(existsSync(f.privateKeyLog)).toBe(failClose);
      await f.retry();
      expect(error.cleanupIncomplete).toBe(false);
      expect(error.cleanupResources).toEqual([]);
      expect(JSON.stringify(projectAnalysisError(error))).not.toContain(
        "fixture-credential",
      );
    }
    expect(existsSync(f.privateKeyLog)).toBe(false);
  },
);
