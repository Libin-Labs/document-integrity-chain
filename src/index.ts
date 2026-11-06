export interface IntegrityEntry {
  readonly index: number;
  readonly timestamp: number;
  readonly payload: Uint8Array;
  readonly previousHash: string;
  readonly hash: string;
}

export interface IntegrityChain {
  append(payload: Uint8Array, timestamp?: number): Promise<IntegrityEntry>;
  entries(): IntegrityEntry[];
}

export interface IntegrityVerification {
  valid: boolean;
  verifiedEntries: number;
  error?: string;
}

const ZERO_HASH = '0'.repeat(64);
const MAX_ENTRIES = 100_000;
const MAX_PAYLOAD_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;

function subtleProvider(subtle?: SubtleCrypto): SubtleCrypto {
  const value = subtle ?? globalThis.crypto?.subtle;
  if (!value) throw new Error('WebCrypto SubtleCrypto is unavailable.');
  return value;
}

function hashBytes(value: string): Uint8Array {
  if (!/^[a-f0-9]{64}$/.test(value))
    throw new TypeError('Chain hashes must be lowercase SHA-256 hex.');
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index++)
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function source(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function material(
  index: number,
  timestamp: number,
  previousHash: string,
  payload: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(4 + 4 + 8 + 32 + 4 + payload.length);
  result.set([0x4c, 0x50, 0x49, 0x31], 0);
  const view = new DataView(result.buffer);
  view.setUint32(4, index);
  view.setBigInt64(8, BigInt(timestamp));
  result.set(hashBytes(previousHash), 16);
  view.setUint32(48, payload.length);
  result.set(payload, 52);
  return result;
}

async function digest(
  index: number,
  timestamp: number,
  previousHash: string,
  payload: Uint8Array,
  subtle: SubtleCrypto,
): Promise<string> {
  return hex(
    new Uint8Array(
      await subtle.digest('SHA-256', source(material(index, timestamp, previousHash, payload))),
    ),
  );
}

function timestampValue(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000)
    throw new RangeError('Timestamp must be a nonnegative safe Unix millisecond value.');
  return value;
}

export function createIntegrityChain(subtleInput?: SubtleCrypto): IntegrityChain {
  const subtle = subtleProvider(subtleInput);
  const entries: IntegrityEntry[] = [];
  let busy = false;
  let totalBytes = 0;
  return {
    async append(input, timestamp = Date.now()) {
      if (busy) throw new Error('Concurrent integrity-chain appends are not allowed.');
      if (!(input instanceof Uint8Array)) throw new TypeError('Payload must be a Uint8Array.');
      if (input.length > MAX_PAYLOAD_BYTES)
        throw new RangeError('Payload exceeds the 1 MiB limit.');
      if (input.length > MAX_TOTAL_BYTES - totalBytes)
        throw new RangeError('Integrity chain total payload limit exceeded.');
      if (entries.length >= MAX_ENTRIES) throw new RangeError('Integrity chain capacity exceeded.');
      const time = timestampValue(timestamp);
      if (entries.length && time < entries[entries.length - 1]!.timestamp)
        throw new RangeError('Entry timestamps must be nondecreasing.');
      const payload = new Uint8Array(input);
      const previousHash = entries.length ? entries[entries.length - 1]!.hash : ZERO_HASH;
      const index = entries.length;
      busy = true;
      try {
        const hash = await digest(index, time, previousHash, payload, subtle);
        const entry = Object.freeze({ index, timestamp: time, payload, previousHash, hash });
        entries.push(entry);
        totalBytes += payload.length;
        return Object.freeze({ ...entry, payload: new Uint8Array(payload) });
      } finally {
        busy = false;
      }
    },
    entries() {
      return entries.map((entry) =>
        Object.freeze({ ...entry, payload: new Uint8Array(entry.payload) }),
      );
    },
  };
}

export async function verifyIntegrityChain(
  input: readonly IntegrityEntry[],
  subtleInput?: SubtleCrypto,
): Promise<IntegrityVerification> {
  if (!Array.isArray(input) || input.length > MAX_ENTRIES)
    throw new TypeError('Integrity entries must be an array within the 100000-entry limit.');
  const subtle = subtleProvider(subtleInput);
  let previousHash = ZERO_HASH;
  let previousTimestamp = 0;
  let totalBytes = 0;
  for (let index = 0; index < input.length; index++) {
    const entry = input[index]!;
    if (
      !entry ||
      entry.index !== index ||
      !Number.isSafeInteger(entry.timestamp) ||
      entry.timestamp < previousTimestamp ||
      !(entry.payload instanceof Uint8Array) ||
      entry.payload.length > MAX_PAYLOAD_BYTES ||
      entry.previousHash !== previousHash ||
      !/^[a-f0-9]{64}$/.test(entry.hash)
    )
      return Object.freeze({
        valid: false,
        verifiedEntries: index,
        error: `Invalid chain entry at index ${index}.`,
      });
    totalBytes += entry.payload.length;
    if (totalBytes > MAX_TOTAL_BYTES)
      return Object.freeze({
        valid: false,
        verifiedEntries: index,
        error: 'Chain payload limit exceeded.',
      });
    const expected = await digest(
      index,
      entry.timestamp,
      previousHash,
      new Uint8Array(entry.payload),
      subtle,
    );
    if (expected !== entry.hash)
      return Object.freeze({
        valid: false,
        verifiedEntries: index,
        error: `Hash mismatch at index ${index}.`,
      });
    previousHash = entry.hash;
    previousTimestamp = entry.timestamp;
  }
  return Object.freeze({ valid: true, verifiedEntries: input.length });
}
