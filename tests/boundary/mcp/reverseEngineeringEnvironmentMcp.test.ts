import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Client } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { createProviderEnvironmentMcpHarness } from "../../support/reverseDebuggerMcpTestHelpers.js";

const writeProvider = async (path: string, output: string): Promise<void> => {
  await writeFile(
    path,
    `#!${process.execPath}\nprocess.stdout.write('${output}');\n`,
  );
  await chmod(path, 0o755);
};

const connectProviderClient = (options: {
  readonly directory: string;
  readonly clientName: string;
  readonly configuredProvider: string;
  readonly providerEnvironment?: { REA_RIZIN_COMMAND: string };
}) =>
  createProviderEnvironmentMcpHarness({
    directory: options.directory,
    clientName: options.clientName,
    serverOptions: {
      environment: { REA_RIZIN_COMMAND: options.configuredProvider },
      ...(options.providerEnvironment === undefined
        ? {}
        : { providerEnvironment: options.providerEnvironment }),
    },
  });

const executeRizinCommand = async (
  client: Client,
  artifact: string,
): Promise<Awaited<ReturnType<Client["callTool"]>>> => {
  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: artifact, command: "iI" },
  });
  expect(response.isError).not.toBe(true);
  return response;
};

it("uses the captured server environment to resolve reverse-engineering providers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-environment-"));
  const provider = join(directory, "selected-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  await writeProvider(provider, "captured-environment-provider");

  const { client } = await connectProviderClient({
    directory,
    clientName: "reverse-provider-environment",
    configuredProvider: provider,
  });
  const response = await executeRizinCommand(client, artifact);
  expect(JSON.stringify(response.structuredContent)).toContain(
    "captured-environment-provider",
  );
});

it("prefers an explicit provider environment over the captured server environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-override-"));
  const configured = join(directory, "captured-rizin");
  const override = join(directory, "override-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  for (const [path, output] of [
    [configured, "captured"],
    [override, "explicit-override"],
  ] as const) {
    await writeProvider(path, output);
  }
  const { client } = await connectProviderClient({
    directory,
    clientName: "reverse-provider-override",
    configuredProvider: configured,
    providerEnvironment: { REA_RIZIN_COMMAND: override },
  });

  const response = await executeRizinCommand(client, artifact);
  expect(JSON.stringify(response.structuredContent)).toContain(
    "explicit-override",
  );
  expect(JSON.stringify(response.structuredContent)).not.toContain(
    '"captured"',
  );
});

it("snapshots an explicit provider environment when the server is created", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-snapshot-"));
  const configured = join(directory, "captured-rizin");
  const override = join(directory, "explicit-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  for (const [path, output] of [
    [configured, "captured"],
    [override, "explicit-snapshot"],
  ] as const) {
    await writeProvider(path, output);
  }
  const providerEnvironment = { REA_RIZIN_COMMAND: override };
  const { client } = await connectProviderClient({
    directory,
    clientName: "reverse-provider-snapshot",
    configuredProvider: configured,
    providerEnvironment,
  });
  providerEnvironment.REA_RIZIN_COMMAND = configured;

  const response = await executeRizinCommand(client, artifact);
  expect(JSON.stringify(response.structuredContent)).toContain(
    "explicit-snapshot",
  );
  expect(JSON.stringify(response.structuredContent)).not.toContain(
    '"captured"',
  );
});

const realRizin = process.env.REA_RIZIN_COMMAND;

it.skipIf(realRizin === undefined).each([
  {
    name: "default disassembly",
    command: "e asm.arch=x86; e asm.bits=64; pd 2",
    colored: false,
  },
  {
    name: "explicit color",
    command: "e scr.color=1; e asm.arch=x86; e asm.bits=64; pd 2",
    colored: true,
  },
  { name: "JSON bytes", command: "pxj 2", colored: false },
])("preserves real Rizin output with $name", async ({ command, colored }) => {
  if (realRizin === undefined) throw new Error("REA_RIZIN_COMMAND is required");
  const directory = await createTestTempDirectory("rea-rizin-color-");
  const artifact = join(directory, "instructions.bin");
  await writeFile(artifact, Buffer.from([0x90, 0xc3]));
  const { client } = await connectProviderClient({
    directory,
    clientName: "rizin-color-test",
    configuredProvider: realRizin,
    providerEnvironment: { ...process.env, REA_RIZIN_COMMAND: realRizin },
  });
  const args = ["-N", "-q", "-e", "scr.color=0", "-c", command, artifact];
  const direct = await promisify(execFile)(realRizin, args, {
    timeout: 10_000,
  });
  expect(direct.stdout.includes("\u001b[")).toBe(colored);
  if (command === "pxj 2")
    expect(JSON.parse(direct.stdout)).toEqual([0x90, 0xc3]);
  else {
    expect(direct.stdout).toContain("nop");
    expect(direct.stdout).toContain("ret");
  }
  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: artifact, command },
  });
  expect(response.isError).not.toBe(true);
  expect(response.structuredContent).toMatchObject({
    parameters: { command, command_arguments: args },
    raw_result: { stdout: direct.stdout, stderr: direct.stderr, exit_code: 0 },
    normalized_result: {
      stdout: direct.stdout,
      stderr: direct.stderr,
      exit_code: 0,
    },
  });
});
