import { z } from "zod";
import { AnalysisResourceConstraintError } from "../analysisErrorCore.js";
import { err, ok, type Result } from "../result.js";

/** NSS key log labels REA classifies; TShark applies its own parser to the same file. */
export const TLS_KEY_LOG_LABELS = [
  "CLIENT_RANDOM",
  "CLIENT_EARLY_TRAFFIC_SECRET",
  "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
  "SERVER_HANDSHAKE_TRAFFIC_SECRET",
  "CLIENT_TRAFFIC_SECRET_0",
  "SERVER_TRAFFIC_SECRET_0",
  "EARLY_EXPORTER_SECRET",
  "EXPORTER_SECRET",
] as const;
type TlsKeyLogLabel = (typeof TLS_KEY_LOG_LABELS)[number];

/** Resident key-log admission; the same bound as a selected capture. */
export const TLS_KEY_LOG_MAX_BYTES = 32 * 1024 * 1024;

const count = z.number().int().nonnegative();
const labelCount = count.describe("Recognized lines with this label");
const summaryShape = {
  lines: z.strictObject({
    total: count,
    comment_or_blank: count,
    unrecognized: count.describe(
      "Lines that are not comments, blank, or a recognized label with a 32-byte hex client random and a hex secret of the label's length. Never echoed; TShark may still use them.",
    ),
  }),
  labels: z.strictObject({
    CLIENT_RANDOM: labelCount,
    CLIENT_EARLY_TRAFFIC_SECRET: labelCount,
    CLIENT_HANDSHAKE_TRAFFIC_SECRET: labelCount,
    SERVER_HANDSHAKE_TRAFFIC_SECRET: labelCount,
    CLIENT_TRAFFIC_SECRET_0: labelCount,
    SERVER_TRAFFIC_SECRET_0: labelCount,
    EARLY_EXPORTER_SECRET: labelCount,
    EXPORTER_SECRET: labelCount,
  }),
  client_randoms: z.strictObject({
    in_key_log: count.describe(
      "Distinct client randoms on recognized lines. Not compared with recorded handshakes.",
    ),
  }),
  secret_values: z.literal("not-returned"),
};
const summarySchema = z.strictObject(summaryShape);
export type TlsKeyLogSummary = z.infer<typeof summarySchema>;

/** Key-log identity and counts; secrets, client randoms and line text are never fields. */
export const tlsKeyLogReportSchema = z
  .strictObject({
    path: z.string(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: count,
    ...summaryShape,
  })
  .superRefine((report, context) => {
    const recognized = Object.values(report.labels).reduce(
      (sum, value) => sum + value,
      0,
    );
    if (
      report.lines.total !==
        report.lines.comment_or_blank +
          report.lines.unrecognized +
          recognized ||
      report.client_randoms.in_key_log > recognized ||
      recognized > 0 !== report.client_randoms.in_key_log > 0
    )
      context.addIssue({
        code: "custom",
        path: ["lines"],
        message:
          "Key-log line, label and client-random counts must describe one parse",
      });
  });

const LABEL_BYTES = TLS_KEY_LOG_LABELS.map((label) =>
  Uint8Array.from(label, (character) => character.charCodeAt(0)),
);
const LONGEST_LABEL = Math.max(...LABEL_BYTES.map(({ length }) => length));
const CLIENT_RANDOM_HEX = 64;
// CLIENT_RANDOM carries a 48-byte TLS 1.2 master secret. TLS 1.3 secrets are
// one hash output: 32 (SHA-256) or 48 (SHA-384) bytes; 64 is also admitted.
const secretHexAdmitted = (label: TlsKeyLogLabel, length: number): boolean =>
  label === "CLIENT_RANDOM"
    ? length === 96
    : length === 64 || length === 96 || length === 128;
const LF = 0x0a;
const CR = 0x0d;
const SPACE = 0x20;
const TAB = 0x09;
const HASH = 0x23;
const COMMENT_OR_BLANK = -1;
const UNRECOGNIZED = -2;

const isHex = (byte: number | undefined): boolean =>
  byte !== undefined &&
  ((byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x46) ||
    (byte >= 0x61 && byte <= 0x66));
const allHex = (bytes: Uint8Array, start: number, end: number): boolean => {
  for (let index = start; index < end; index++)
    if (!isHex(bytes[index])) return false;
  return true;
};

/** Match a label by bytes, allocating nothing for unrecognized text. */
const labelAt = (bytes: Uint8Array, start: number, end: number): number => {
  for (let index = 0; index < LABEL_BYTES.length; index++) {
    const candidate = LABEL_BYTES[index];
    if (candidate?.length !== end - start) continue;
    let offset = 0;
    while (
      offset < candidate.length &&
      bytes[start + offset] === candidate[offset]
    )
      offset++;
    if (offset === candidate.length) return index;
  }
  return UNRECOGNIZED;
};

/** Classify one line by label index or negative code, without copying its text. */
const classify = (bytes: Uint8Array, start: number, end: number): number => {
  let last = end;
  if (last > start && bytes[last - 1] === CR) last--;
  while (last > start && (bytes[last - 1] === SPACE || bytes[last - 1] === TAB))
    last--;
  if (last === start || bytes[start] === HASH) return COMMENT_OR_BLANK;
  const labelLimit = Math.min(last, start + LONGEST_LABEL + 1);
  let labelEnd = start;
  while (labelEnd < labelLimit && bytes[labelEnd] !== SPACE) labelEnd++;
  if (labelEnd === labelLimit) return UNRECOGNIZED;
  const index = labelAt(bytes, start, labelEnd);
  if (index < 0) return UNRECOGNIZED;
  const label = TLS_KEY_LOG_LABELS[index];
  const randomStart = labelEnd + 1;
  const secretStart = randomStart + CLIENT_RANDOM_HEX + 1;
  return label !== undefined &&
    secretStart < last &&
    bytes[secretStart - 1] === SPACE &&
    allHex(bytes, randomStart, secretStart - 1) &&
    secretHexAdmitted(label, last - secretStart) &&
    allHex(bytes, secretStart, last)
    ? index
    : UNRECOGNIZED;
};

/**
 * Count NSS key log (SSLKEYLOGFILE) lines and labels in one linear scan.
 * Secrets, client randoms and line text are examined only to classify lines
 * and never leave this function, including through errors.
 */
export const summarizeTlsKeyLog = (
  bytes: Uint8Array,
  operation: string,
): Result<TlsKeyLogSummary, AnalysisResourceConstraintError> => {
  if (bytes.length > TLS_KEY_LOG_MAX_BYTES)
    return err(
      new AnalysisResourceConstraintError(
        operation,
        "file-size",
        `TLS key log exceeds ${String(TLS_KEY_LOG_MAX_BYTES)} bytes.`,
        { tls_key_log_bytes: TLS_KEY_LOG_MAX_BYTES },
      ),
    );
  const labelCounts = TLS_KEY_LOG_LABELS.map(() => 0);
  const clientRandoms = new Set<string>();
  const lines = { total: 0, comment_or_blank: 0, unrecognized: 0 };
  const decoder = new TextDecoder("latin1");
  for (let start = 0; start < bytes.length;) {
    let end = start;
    while (end < bytes.length && bytes[end] !== LF) end++;
    const index = classify(bytes, start, end);
    lines.total++;
    if (index === COMMENT_OR_BLANK) lines.comment_or_blank++;
    else if (index === UNRECOGNIZED) lines.unrecognized++;
    else {
      labelCounts[index] = (labelCounts[index] ?? 0) + 1;
      const randomStart = start + (LABEL_BYTES[index]?.length ?? 0) + 1;
      // Hex digits decode identically under every single-byte decoder.
      clientRandoms.add(
        decoder
          .decode(bytes.subarray(randomStart, randomStart + CLIENT_RANDOM_HEX))
          .toLowerCase(),
      );
    }
    start = end + 1;
  }
  const count = (label: TlsKeyLogLabel): number =>
    labelCounts[TLS_KEY_LOG_LABELS.indexOf(label)] ?? 0;
  return ok({
    lines,
    labels: {
      CLIENT_RANDOM: count("CLIENT_RANDOM"),
      CLIENT_EARLY_TRAFFIC_SECRET: count("CLIENT_EARLY_TRAFFIC_SECRET"),
      CLIENT_HANDSHAKE_TRAFFIC_SECRET: count("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
      SERVER_HANDSHAKE_TRAFFIC_SECRET: count("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
      CLIENT_TRAFFIC_SECRET_0: count("CLIENT_TRAFFIC_SECRET_0"),
      SERVER_TRAFFIC_SECRET_0: count("SERVER_TRAFFIC_SECRET_0"),
      EARLY_EXPORTER_SECRET: count("EARLY_EXPORTER_SECRET"),
      EXPORTER_SECRET: count("EXPORTER_SECRET"),
    },
    client_randoms: { in_key_log: clientRandoms.size },
    secret_values: "not-returned",
  });
};
