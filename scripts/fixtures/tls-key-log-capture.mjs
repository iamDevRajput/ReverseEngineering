// Record owned in-process TLS sessions as synthetic Ethernet/IPv4/TCP frames
// plus the NSS key log Node's client reports. No network or external capture.
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { duplexPair } from "node:stream";
import { connect, TLSSocket } from "node:tls";
import { promisify } from "node:util";

const SERVER_PORT = 443;
const SEGMENT_BYTES = 1400;

/** Create an ephemeral self-signed P-256 certificate with the host's OpenSSL. */
const certificate = async (directory) => {
  const key = join(directory, "tls-fixture-key.pem");
  const cert = join(directory, "tls-fixture-cert.pem");
  await promisify(execFile)(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-subj",
      "/CN=rea.test",
      "-addext",
      "subjectAltName=DNS:rea.test",
      "-days",
      "1",
      "-keyout",
      key,
      "-out",
      cert,
    ],
    { timeout: 30000 },
  );
  return { key: await readFile(key), cert: await readFile(cert) };
};

/** Run one HTTP/1.1 exchange over TLS, recording ciphertext in arrival order. */
const recordSession = ({ key, cert }, session) =>
  new Promise((resolve, reject) => {
    const [clientEnd, clientRelay] = duplexPair();
    const [serverRelay, serverEnd] = duplexPair();
    const segments = [];
    const relay = (from, to, fromClient) => {
      from.on("data", (bytes) => {
        segments.push({ fromClient, bytes: Buffer.from(bytes) });
        to.write(bytes);
      });
      from.on("end", () => to.end());
    };
    relay(clientRelay, serverRelay, true);
    relay(serverRelay, clientRelay, false);
    const keyLog = [];
    const server = new TLSSocket(serverEnd, {
      isServer: true,
      key,
      cert,
      ALPNProtocols: ["http/1.1"],
      minVersion: "TLSv1.2",
    });
    const client = connect({
      socket: clientEnd,
      servername: "rea.test",
      ca: cert,
      ALPNProtocols: ["http/1.1"],
      minVersion: "TLSv1.2",
      maxVersion: session.version,
    });
    client.on("keylog", (line) => keyLog.push(line.toString("latin1").trim()));
    let request = "";
    server.on("data", (bytes) => {
      request += bytes.toString("latin1");
      if (!request.includes("\r\n\r\n")) return;
      server.end(
        `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: session=${session.cookie}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok`,
      );
    });
    let response = "";
    let protocol = null;
    client.on("secureConnect", () => {
      protocol = client.getProtocol();
      client.write(
        `GET ${session.path} HTTP/1.1\r\nHost: rea.test\r\nAuthorization: Bearer ${session.token}\r\nConnection: close\r\n\r\n`,
      );
    });
    client.on("data", (bytes) => {
      response += bytes.toString("latin1");
    });
    let closed = 0;
    const done = () => {
      if (++closed < 2) return;
      if (!response.startsWith("HTTP/1.1 200 OK"))
        reject(new Error(`Unexpected fixture response for ${session.path}`));
      else resolve({ segments, keyLog, protocol });
    };
    for (const socket of [client, server]) {
      socket.on("error", reject);
      socket.on("close", done);
    }
    client.on("end", () => client.end());
  });

const ipv4 = (source, destination, payloadLength) => {
  const header = Buffer.from("450000000001400040060000", "hex");
  header.writeUInt16BE(20 + payloadLength, 2);
  const ip = Buffer.concat([header, source, destination]);
  let checksum = 0;
  for (let i = 0; i < ip.length; i += 2) checksum += ip.readUInt16BE(i);
  while (checksum > 0xffff) checksum = (checksum & 0xffff) + (checksum >>> 16);
  ip.writeUInt16BE(~checksum & 0xffff, 10);
  return ip;
};
const CLIENT_ADDRESS = Buffer.from([192, 0, 2, 10]);
const SERVER_ADDRESS = Buffer.from([192, 0, 2, 20]);
// Destination MAC, source MAC, IPv4 EtherType.
const ETHERNET = {
  client: Buffer.from("0200000000020200000000010800", "hex"),
  server: Buffer.from("0200000000010200000000020800", "hex"),
};

/** Build a SYN handshake and data segments with consistent sequence numbers. */
const tcpFrames = (clientPort, segments) => {
  const state = {
    client: { sequence: 0x10000000, port: clientPort },
    server: { sequence: 0x20000000, port: SERVER_PORT },
  };
  const frame = (fromClient, flags, payload = Buffer.alloc(0)) => {
    const self = fromClient ? state.client : state.server;
    const peer = fromClient ? state.server : state.client;
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(self.port, 0);
    tcp.writeUInt16BE(peer.port, 2);
    tcp.writeUInt32BE(self.sequence >>> 0, 4);
    tcp.writeUInt32BE(flags & 0x10 ? peer.sequence >>> 0 : 0, 8);
    tcp.writeUInt8(0x50, 12);
    tcp.writeUInt8(flags, 13);
    tcp.writeUInt16BE(65535, 14);
    self.sequence += payload.length + (flags & 0x03 ? 1 : 0);
    return Buffer.concat([
      fromClient ? ETHERNET.client : ETHERNET.server,
      ipv4(
        fromClient ? CLIENT_ADDRESS : SERVER_ADDRESS,
        fromClient ? SERVER_ADDRESS : CLIENT_ADDRESS,
        20 + payload.length,
      ),
      tcp,
      payload,
    ]);
  };
  const frames = [frame(true, 0x02), frame(false, 0x12), frame(true, 0x10)];
  for (const { fromClient, bytes } of segments)
    for (let offset = 0; offset < bytes.length; offset += SEGMENT_BYTES)
      frames.push(
        frame(fromClient, 0x18, bytes.subarray(offset, offset + SEGMENT_BYTES)),
      );
  frames.push(frame(true, 0x11), frame(false, 0x11), frame(true, 0x10));
  return frames;
};

/**
 * Record TLS 1.3 and TLS 1.2 sessions whose keys are logged, plus a TLS 1.3
 * session whose keys are deliberately omitted from the returned key log.
 */
export const recordTlsKeyLogCapture = async (directory) => {
  const identity = await certificate(directory);
  const sessions = [
    { version: "TLSv1.3", path: "/rea-tls13", keyed: true, clientPort: 50013 },
    { version: "TLSv1.2", path: "/rea-tls12", keyed: true, clientPort: 50012 },
    {
      version: "TLSv1.3",
      path: "/rea-no-keys",
      keyed: false,
      clientPort: 50014,
    },
  ].map((session, index) => ({
    ...session,
    token: `rea-verifier-token-${index}`,
    cookie: `rea-verifier-cookie-${index}`,
  }));
  const frames = [];
  const recorded = [];
  for (const session of sessions) {
    const result = await recordSession(identity, session);
    if (result.protocol !== session.version)
      throw new Error(
        `Fixture negotiated ${String(result.protocol)}, expected ${session.version}`,
      );
    frames.push(...tcpFrames(session.clientPort, result.segments));
    recorded.push({ ...session, keyLog: result.keyLog });
  }
  return { frames, sessions: recorded };
};
