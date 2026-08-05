import { LoroDoc, VersionVector, decodeImportBlobMeta } from "loro-crdt";
import { CrdtType, type JoinResponseOk } from "loro-protocol";
import type { CrdtAdaptorContext, CrdtDocAdaptor } from "./types";
import {
  aesGcmDecrypt,
  decodeEloContainer,
  decodeEloDeltaPlaintext,
  encodeEloContainer,
  encodeEloDeltaPlaintext,
  encryptDeltaSpan,
  encryptSnapshot,
  EloRecordKind,
  parseEloRecordHeader,
  randomIv12,
  type EloHeader,
  type ParsedEloRecordHeader,
} from "loro-protocol";

export type EloKeyMaterial = Parameters<typeof aesGcmDecrypt>[0];

export interface EloResolvedKey {
  keyId: string;
  key: EloKeyMaterial;
}

/** Application-owned key lookup. Passing no key ID selects the active outbound key. */
export interface EloKeyResolver {
  resolveKey(keyId?: string): Promise<EloResolvedKey | undefined>;
}

/** A small in-memory keyring suitable for applications that already obtain keys elsewhere. */
export class EloKeyring implements EloKeyResolver {
  private readonly keys = new Map<string, EloKeyMaterial>();
  private activeKeyId?: string;

  constructor(keys: Iterable<EloResolvedKey> = [], activeKeyId?: string) {
    for (const { keyId, key } of keys) this.addKey(keyId, key);
    if (activeKeyId !== undefined) this.setActiveKey(activeKeyId);
  }

  addKey(keyId: string, key: EloKeyMaterial): void {
    validateKeyId(keyId);
    const existing = this.keys.get(keyId);
    if (existing !== undefined) {
      if (keyMaterialsEqual(existing, key)) return;
      throw new Error(`ELO key ID already exists: ${keyId}`);
    }
    this.keys.set(keyId, copyKeyMaterial(key));
  }

  removeKey(keyId: string): boolean {
    if (this.activeKeyId === keyId) this.activeKeyId = undefined;
    return this.keys.delete(keyId);
  }

  setActiveKey(keyId: string): void {
    if (!this.keys.has(keyId)) throw new Error(`Unknown ELO key ID: ${keyId}`);
    this.activeKeyId = keyId;
  }

  async resolveKey(keyId?: string): Promise<EloResolvedKey | undefined> {
    const selectedId = keyId ?? this.activeKeyId;
    if (selectedId === undefined) return undefined;
    const key = this.keys.get(selectedId);
    return key === undefined
      ? undefined
      : { keyId: selectedId, key: copyKeyMaterial(key) };
  }
}

export type EloAdaptorErrorKind =
  | "unknown_key"
  | "decrypt_failed"
  | "malformed_record"
  | "import_failed"
  | "encrypt_failed"
  | "pending_evicted";

export interface EloAdaptorError {
  kind: EloAdaptorErrorKind;
  recordKind?: "delta" | "snapshot";
  keyId?: string;
  peerId?: Uint8Array;
  start?: number;
  end?: number;
  cause: Error;
}

export interface EloRetryResult {
  attempted: number;
  imported: number;
  remaining: number;
}

interface DecryptedEloRecord {
  header: ParsedEloRecordHeader;
  blobs: Uint8Array[];
}

type DecryptEloRecordResult =
  | { status: "decrypted"; value: DecryptedEloRecord }
  | { status: "unknown" | "failed" };

export interface EloAdaptorConfig {
  /** Compatibility callback. Prefer keyResolver for multi-key applications. */
  getPrivateKey?: (keyId?: string) => Promise<EloResolvedKey | undefined>;
  keyResolver?: EloKeyResolver;
  pendingEncryptedRecords?: { maxRecords?: number; maxBytes?: number };
  onEloError?: (error: EloAdaptorError) => void;
  ivFactory?: () => Uint8Array;
  onDecryptError?: (
    err: Error,
    meta: { kind: "delta" | "snapshot"; keyId: string }
  ) => void;
  onUpdateError?: (
    updates: Uint8Array[],
    errorCode: number,
    reason?: string
  ) => void;
}

export class EloAdaptor implements CrdtDocAdaptor {
  readonly crdtType = CrdtType.Elo;

  private doc: LoroDoc;
  private ctx?: CrdtAdaptorContext;
  private destroyed = false;
  private config: EloAdaptorConfig;
  private localUpdateUnsubscribe?: () => void;
  private initServerVersion?: VersionVector;
  private hasReachedServerVersion = false;
  private reachServerVersionPromise: {
    promise: Promise<void>;
    resolve: () => void;
    reject: (err: Error) => void;
  };
  private lastSentVV?: Record<string, number>;
  private inboundChain: Promise<void> = Promise.resolve();
  private outboundChain: Promise<void> = Promise.resolve();
  private retryInFlight?: Promise<EloRetryResult>;
  private readonly pendingRecords: Array<{ record: Uint8Array }> = [];
  private pendingBytes = 0;
  private readonly usedIvs = new Set<string>();
  private readonly pendingMaxRecords: number;
  private readonly pendingMaxBytes: number;

  // Overloads to allow (config) or (doc, config)
  constructor(doc: LoroDoc, config: EloAdaptorConfig);
  constructor(config: EloAdaptorConfig);
  constructor(
    docOrConfig: LoroDoc | EloAdaptorConfig,
    maybeConfig?: EloAdaptorConfig
  ) {
    if (docOrConfig instanceof LoroDoc) {
      this.doc = docOrConfig;
      this.config = maybeConfig as EloAdaptorConfig;
    } else {
      this.doc = new LoroDoc();
      this.config = docOrConfig;
    }
    if (!this.config?.keyResolver && !this.config?.getPrivateKey) {
      throw new Error("EloAdaptor requires keyResolver or getPrivateKey");
    }
    this.pendingMaxRecords = parsePendingLimit(
      "maxRecords",
      this.config.pendingEncryptedRecords?.maxRecords,
      128
    );
    this.pendingMaxBytes = parsePendingLimit(
      "maxBytes",
      this.config.pendingEncryptedRecords?.maxBytes,
      8 * 1024 * 1024
    );
    let resolve!: () => void;
    let reject!: (err: Error) => void;
    const promise = new Promise<void>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    this.reachServerVersionPromise = { promise, resolve, reject };
    void this.reachServerVersionPromise.promise.then(
      () => {
        this.hasReachedServerVersion = true;
      },
      () => undefined
    );
  }

  getDoc(): LoroDoc {
    return this.doc;
  }
  waitForReachingServerVersion(): Promise<void> {
    return this.reachServerVersionPromise.promise;
  }
  cmpVersion(v: Uint8Array): 0 | 1 | -1 | undefined {
    try {
      const vv = VersionVector.decode(v);
      return this.doc.version().compare(vv) as 0 | 1 | -1 | undefined;
    } catch {
      return undefined;
    }
  }

  setCtx(ctx: CrdtAdaptorContext): void {
    this.ctx = ctx;
    this.localUpdateUnsubscribe = this.doc.subscribeLocalUpdates(updates => {
      if (this.destroyed || !this.ctx) return;
      void this.enqueueOutbound(() => this.sendLocalUpdate(updates)).catch(
        error => {
          const cause = asError(error);
          this.reportEloError(outboundErrorKind(error), undefined, cause);
          this.reportImportError(cause, []);
        }
      );
    });
  }

  getVersion(): Uint8Array {
    return this.doc.version().encode();
  }

  getAlternativeVersion(_currentVersion: Uint8Array): Uint8Array | undefined {
    return undefined;
  }

  onUpdateError(
    updates: Uint8Array[],
    errorCode: number,
    reason?: string
  ): void {
    this.config.onUpdateError?.(updates, errorCode, reason);
  }

  async handleJoinOk(res: JoinResponseOk): Promise<void> {
    if (this.destroyed) return;
    try {
      await this.enqueueOutbound(async () => {
        const serverVersion =
          res.version.length > 0
            ? VersionVector.decode(res.version)
            : undefined;
        this.initServerVersion = serverVersion;

        const startJson: Record<string, number> = serverVersion
          ? vvToObject(serverVersion)
          : {};
        this.lastSentVV = startJson;
        const sent = await this.packageAndSendForwardDeltas(startJson);
        if (!sent) {
          const sv = serverVersion ?? null;
          if (sv === null) {
            await this.sendSnapshot();
          } else {
            const cmp = this.doc.version().compare(sv);
            if (cmp != null && cmp >= 0) await this.sendSnapshot();
          }
        }
        if (!serverVersion) {
          this.reachServerVersionPromise.resolve();
          return;
        }

        const comparison = this.doc.version().compare(serverVersion);
        if (comparison != null && comparison >= 0) {
          this.reachServerVersionPromise.resolve();
        }
      });
    } catch (error) {
      this.ctx?.onJoinFailed(asError(error).message);
      throw error;
    }
  }

  applyUpdate(updates: Uint8Array[]): void {
    if (this.destroyed || !updates?.length) return;
    for (const containerBytes of updates) {
      this.inboundChain = this.inboundChain.then(async () => {
        if (this.destroyed) return;
        await this.importEloContainer(containerBytes);
        if (!this.destroyed) this.resolveServerVersionAfterImport();
      });
      this.inboundChain = this.inboundChain.catch(error => {
        this.reportImportError(asError(error), []);
      });
    }
  }

  get pendingEncryptedRecordCount(): number {
    return this.pendingRecords.length;
  }

  async retryPendingEncryptedRecords(): Promise<EloRetryResult> {
    if (this.retryInFlight) return this.retryInFlight;
    const retry = this.performPendingRetry();
    this.retryInFlight = retry;
    try {
      return await retry;
    } finally {
      if (this.retryInFlight === retry) this.retryInFlight = undefined;
    }
  }

  private async performPendingRetry(): Promise<EloRetryResult> {
    let result: EloRetryResult = {
      attempted: 0,
      imported: 0,
      remaining: this.pendingRecords.length,
    };
    this.inboundChain = this.inboundChain.then(async () => {
      if (this.destroyed) return;
      const pending = this.pendingRecords.splice(0);
      this.pendingBytes = 0;
      let imported = 0;
      for (const item of pending) {
        const outcome = await this.importEloRecord(item.record, false);
        if (this.destroyed) return;
        if (outcome === "imported") imported++;
        if (outcome === "unknown") this.enqueuePending(item.record, false);
      }
      this.resolveServerVersionAfterImport();
      result = {
        attempted: pending.length,
        imported,
        remaining: this.pendingRecords.length,
      };
    });
    await this.inboundChain;
    return result;
  }

  /** Publish a genuine snapshot with the active outbound key. */
  async publishSnapshot(): Promise<void> {
    if (this.destroyed) return;
    try {
      await this.enqueueOutbound(() => this.sendSnapshot());
    } catch (error) {
      const cause = asError(error);
      this.reportEloError(outboundErrorKind(error), undefined, cause);
      this.reportImportError(cause, []);
      throw error;
    }
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.localUpdateUnsubscribe?.();
    this.localUpdateUnsubscribe = undefined;
    this.ctx = undefined;
    this.pendingRecords.splice(0);
    this.pendingBytes = 0;
    this.usedIvs.clear();
    if (!this.hasReachedServerVersion) {
      this.reachServerVersionPromise.reject(
        new Error("EloAdaptor destroyed before reaching the server version")
      );
    }
  }

  private enqueueOutbound<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.outboundChain.then(operation);
    this.outboundChain = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private async sendLocalUpdate(updates: Uint8Array): Promise<void> {
    let startVVObj: Record<string, number> | undefined;
    let endVVObj: Record<string, number> | undefined;
    try {
      const meta = decodeImportBlobMeta(updates, false);
      startVVObj = vvToObject(meta.partialStartVersionVector);
      endVVObj = vvToObject(meta.partialEndVersionVector);
    } catch {
      await this.sendSnapshot();
      return;
    }

    const spans = computeSpansFromVV(
      startVVObj ?? this.lastSentVV ?? {},
      endVVObj ?? vvToObject(this.doc.version())
    );
    if (spans.length === 1) {
      const { keyId, key } = await this.resolveOutboundKey();
      const span = spans[0];
      if (!span) return;
      const peer = toPeerIdString(span.peer);
      const { record } = await encryptDeltaSpan(
        encodeEloDeltaPlaintext([updates]),
        {
          peerId: new TextEncoder().encode(peer),
          start: span.start,
          end: span.start + span.length,
          keyId,
          iv: this.nextIv(keyId),
        },
        key
      );
      if (!this.destroyed) this.ctx?.send([encodeEloContainer([record])]);
      this.lastSentVV = endVVObj ?? vvToObject(this.doc.version());
      return;
    }

    const sent = await this.packageAndSendForwardDeltas(startVVObj, endVVObj);
    if (!sent) await this.sendSnapshot();
  }

  private nextIv(keyId: string): Uint8Array {
    const iv = this.config.ivFactory?.() ?? randomIv12();
    if (iv.byteLength !== 12) {
      throw new EloOutboundError("encrypt_failed", "IV must be 12 bytes");
    }
    if (this.config.ivFactory) {
      const fingerprint = `${keyId}:${bytesFingerprint(iv)}`;
      if (this.usedIvs.has(fingerprint)) {
        throw new EloOutboundError(
          "encrypt_failed",
          "ELO IV reuse detected for the same key; encryption was not attempted"
        );
      }
      this.usedIvs.add(fingerprint);
    }
    return iv;
  }

  private async sendSnapshot(): Promise<void> {
    const { keyId, key } = await this.resolveOutboundKey();
    const mode = "snapshot";
    const plaintext = this.doc.export({ mode });
    const vvObj = vvToObject(this.doc.version());
    const encoder = new TextEncoder();
    const vvEntries: Array<{ peerId: Uint8Array; counter: number }> =
      Object.keys(vvObj).map(peer => ({
        peerId: encoder.encode(peer),
        counter: vvObj[peer],
      }));
    const { record } = await encryptSnapshot(
      plaintext,
      { vv: vvEntries, keyId, iv: this.nextIv(keyId) },
      key
    );
    const container = encodeEloContainer([record]);
    if (!this.destroyed) this.ctx?.send([container]);
  }

  private async packageAndSendForwardDeltas(
    startVV?: Record<string, number>,
    endVVOverride?: Record<string, number>
  ): Promise<boolean> {
    // Compute spans using only version vectors: for each peer, [start, end)
    const start: Record<string, number> = startVV ?? this.lastSentVV ?? {};
    const end: Record<string, number> =
      endVVOverride ?? vvToObject(this.doc.version());
    const spans = computeSpansFromVV(start, end);
    if (spans.length === 0) return false;

    const { keyId, key } = await this.resolveOutboundKey();
    const records: Uint8Array[] = [];
    for (const s of spans) {
      const peer = s.peer;
      const startCounter = s.start;
      const length = s.length;
      const endCounter = startCounter + length;
      const peerIdBytes = new TextEncoder().encode(String(peer));
      const plaintext = this.doc.export({
        mode: "updates-in-range",
        spans: [
          {
            id: { peer: toPeerIdString(peer), counter: startCounter },
            len: length,
          },
        ],
      });
      const { record } = await encryptDeltaSpan(
        encodeEloDeltaPlaintext([plaintext]),
        {
          peerId: peerIdBytes,
          start: startCounter,
          end: endCounter,
          keyId,
          iv: this.nextIv(keyId),
        },
        key
      );
      records.push(record);
    }

    if (records.length === 0) return false;
    const container = encodeEloContainer(records);
    if (this.destroyed) return false;
    this.ctx?.send([container]);
    this.lastSentVV = end;
    return true;
  }

  private async resolveKey(
    keyId?: string
  ): Promise<EloResolvedKey | undefined> {
    let resolved: EloResolvedKey | undefined;
    try {
      resolved = this.config.keyResolver
        ? await this.config.keyResolver.resolveKey(keyId)
        : await this.config.getPrivateKey?.(keyId);
    } catch (error) {
      throw new EloOutboundError(
        "unknown_key",
        keyId === undefined
          ? "Failed to resolve the active outbound ELO key"
          : `Failed to resolve ELO key ID: ${keyId}`,
        error
      );
    }
    if (
      resolved !== undefined &&
      keyId !== undefined &&
      resolved.keyId !== keyId
    ) {
      throw new EloOutboundError(
        "unknown_key",
        `ELO resolver returned key ID ${resolved.keyId} for requested ID ${keyId}`
      );
    }
    return resolved;
  }

  private async resolveOutboundKey(): Promise<EloResolvedKey> {
    const resolved = await this.resolveKey();
    if (resolved === undefined) {
      throw new EloOutboundError(
        "unknown_key",
        "No active outbound ELO key is available"
      );
    }
    validateKeyId(resolved.keyId);
    return resolved;
  }

  private async importEloContainer(containerBytes: Uint8Array): Promise<void> {
    let records: Uint8Array[];
    try {
      records = decodeEloContainer(containerBytes);
    } catch (error) {
      this.reportEloError("malformed_record", undefined, asError(error));
      this.reportImportError(asError(error), []);
      return;
    }

    const decrypted: DecryptedEloRecord[] = [];
    let failed = false;
    for (const record of records) {
      const result = await this.decryptEloRecord(record, true);
      if (result.status === "decrypted") decrypted.push(result.value);
      if (result.status === "failed") failed = true;
    }
    if (failed || decrypted.length === 0) return;
    this.importDecryptedRecords(decrypted);
  }

  private async importEloRecord(
    record: Uint8Array,
    queueUnknown: boolean
  ): Promise<"imported" | "unknown" | "failed"> {
    const result = await this.decryptEloRecord(record, queueUnknown);
    if (result.status !== "decrypted") return result.status;
    return this.importDecryptedRecords([result.value]) ? "imported" : "failed";
  }

  private async decryptEloRecord(
    record: Uint8Array,
    queueUnknown: boolean
  ): Promise<DecryptEloRecordResult> {
    let header: ParsedEloRecordHeader;
    try {
      header = parseEloRecordHeader(record);
      validateParsedHeader(header.header);
    } catch (error) {
      this.reportEloError("malformed_record", undefined, asError(error));
      this.reportImportError(asError(error), []);
      return { status: "failed" };
    }

    let resolved: EloResolvedKey | undefined;
    let unknownCause: Error | undefined;
    try {
      resolved = await this.resolveKey(header.keyId);
    } catch (error) {
      unknownCause = asError(error);
    }
    if (this.destroyed) return { status: "failed" };
    if (resolved === undefined) {
      const added = queueUnknown ? this.enqueuePending(record, true) : false;
      if (added) {
        this.reportEloError(
          "unknown_key",
          header.header,
          unknownCause ?? new Error(`Unknown ELO key ID: ${header.keyId}`)
        );
      }
      return { status: "unknown" };
    }

    let plaintext: Uint8Array;
    try {
      plaintext = await aesGcmDecrypt(
        resolved.key,
        header.iv,
        header.ct,
        header.aad
      );
    } catch (error) {
      this.reportEloError("decrypt_failed", header.header, asError(error));
      return { status: "failed" };
    }
    if (this.destroyed) return { status: "failed" };

    let blobs = [plaintext];
    if (header.kind === EloRecordKind.DeltaSpan) {
      try {
        blobs = decodeEloDeltaPlaintext(plaintext);
      } catch {
        // Temporary compatibility path for authenticated pre-canonical records.
      }
    }
    return { status: "decrypted", value: { header, blobs } };
  }

  private importDecryptedRecords(records: DecryptedEloRecord[]): boolean {
    if (this.destroyed) return false;
    const blobs = records.flatMap(record => record.blobs);
    if (blobs.length === 0) return true;
    try {
      // Validate the whole authenticated container against a temporary clone so
      // a malformed later record cannot partially mutate the live document.
      const candidate = new LoroDoc();
      candidate.import(this.doc.export({ mode: "snapshot" }));
      candidate.importBatch(blobs);
      this.doc.importBatch(blobs);
      return true;
    } catch (error) {
      const cause = asError(error);
      this.reportEloError("import_failed", records[0]?.header.header, cause);
      this.reportImportError(cause, []);
      return false;
    }
  }

  private enqueuePending(record: Uint8Array, reportEviction: boolean): boolean {
    if (this.pendingRecords.some(item => bytesEqual(item.record, record))) {
      return false;
    }
    const copy = new Uint8Array(record);
    this.pendingRecords.push({ record: copy });
    this.pendingBytes += copy.byteLength;
    while (
      this.pendingRecords.length > this.pendingMaxRecords ||
      this.pendingBytes > this.pendingMaxBytes
    ) {
      const evicted = this.pendingRecords.shift();
      if (!evicted) break;
      this.pendingBytes -= evicted.record.byteLength;
      if (reportEviction) {
        let header: EloHeader | undefined;
        try {
          header = parseEloRecordHeader(evicted.record).header;
        } catch {
          // Pending records were parsed before insertion.
        }
        this.reportEloError(
          "pending_evicted",
          header,
          new Error("Pending encrypted ELO record evicted by configured bounds")
        );
      }
    }
    return true;
  }

  private reportEloError(
    kind: EloAdaptorErrorKind,
    header: EloHeader | undefined,
    cause: Error
  ): void {
    let recordKind: "delta" | "snapshot" | undefined;
    if (header) {
      recordKind =
        header.kind === EloRecordKind.Snapshot ? "snapshot" : "delta";
    }
    const error: EloAdaptorError = {
      kind,
      recordKind,
      keyId: header?.keyId,
      peerId:
        header?.kind === EloRecordKind.DeltaSpan ? header.peerId : undefined,
      start:
        header?.kind === EloRecordKind.DeltaSpan ? header.start : undefined,
      end: header?.kind === EloRecordKind.DeltaSpan ? header.end : undefined,
      cause,
    };
    try {
      this.config.onEloError?.(error);
    } catch (callbackError) {
      this.reportImportError(
        new Error("onEloError callback failed", { cause: callbackError }),
        []
      );
    }
    if (kind === "unknown_key" || kind === "decrypt_failed") {
      try {
        this.config.onDecryptError?.(cause, {
          kind: recordKind ?? "delta",
          keyId: header?.keyId ?? "",
        });
      } catch (callbackError) {
        this.reportImportError(
          new Error("onDecryptError callback failed", { cause: callbackError }),
          []
        );
      }
    }
  }

  private reportImportError(error: Error, source: Uint8Array[]): void {
    try {
      this.ctx?.onImportError(error, source);
    } catch {
      // Application callback failures must not abort ordered import/retry work.
    }
  }

  private resolveServerVersionAfterImport(): void {
    if (!this.initServerVersion || this.hasReachedServerVersion) return;
    const cmp = this.doc.version().compare(this.initServerVersion);
    if (cmp != null && cmp >= 0) this.reachServerVersionPromise.resolve();
  }
}

class EloOutboundError extends Error {
  constructor(
    readonly kind: "unknown_key" | "encrypt_failed",
    message: string,
    cause?: unknown
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "EloOutboundError";
  }
}

function outboundErrorKind(error: unknown): "unknown_key" | "encrypt_failed" {
  return error instanceof EloOutboundError ? error.kind : "encrypt_failed";
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function validateKeyId(keyId: string): void {
  const length = new TextEncoder().encode(keyId).byteLength;
  if (length > 64) throw new Error("ELO key ID must be at most 64 UTF-8 bytes");
}

function copyKeyMaterial(key: EloKeyMaterial): EloKeyMaterial {
  return key instanceof Uint8Array ? new Uint8Array(key) : key;
}

function keyMaterialsEqual(
  left: EloKeyMaterial,
  right: EloKeyMaterial
): boolean {
  if (left instanceof Uint8Array && right instanceof Uint8Array) {
    return bytesEqual(left, right);
  }
  return left === right;
}

function parsePendingLimit(
  name: string,
  value: number | undefined,
  defaultValue: number
): number {
  if (value === undefined) return defaultValue;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(
      `pendingEncryptedRecords.${name} must be a non-negative safe integer`
    );
  }
  return value;
}

function validateParsedHeader(header: EloHeader): void {
  validateKeyId(header.keyId);
  if (header.iv.byteLength !== 12) throw new Error("ELO IV must be 12 bytes");
  if (header.kind === EloRecordKind.DeltaSpan) {
    if (header.peerId.byteLength > 64)
      throw new Error("ELO peer ID is too long");
    if (!(header.end > header.start)) {
      throw new Error("ELO delta span end must be greater than start");
    }
  } else {
    for (const entry of header.vv) {
      if (entry.peerId.byteLength > 64) {
        throw new Error("ELO snapshot peer ID is too long");
      }
    }
    for (let index = 1; index < header.vv.length; index++) {
      if (
        compareBytes(header.vv[index - 1].peerId, header.vv[index].peerId) >= 0
      ) {
        throw new Error("ELO snapshot version vector must be strictly sorted");
      }
    }
  }
}

function bytesFingerprint(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.byteLength - right.byteLength;
}

// Compute spans from start and end version vectors represented as plain objects
// start/end: { [peerId: string]: counter }
function computeSpansFromVV(
  start: Record<string, number>,
  end: Record<string, number>
): Array<{ peer: string; start: number; length: number }> {
  const peers = new Set<string>([...Object.keys(start), ...Object.keys(end)]);
  const spans: Array<{ peer: string; start: number; length: number }> = [];
  for (const peer of peers) {
    const s = start[peer] ?? 0;
    const e = end[peer] ?? 0;
    if (e > s) {
      spans.push({ peer, start: s, length: e - s });
    }
  }
  return spans;
}

// Convert arbitrary string peer id into Loro PeerID template (numeric string)
function toPeerIdString(peer: string): `${number}` {
  if (!/^\d+$/.test(peer)) {
    throw new Error(`Invalid PeerID: ${peer}`);
  }
  return peer as `${number}`;
}

function vvToObject(vvLike: VersionVector): Record<string, number> {
  const json = vvLike.toJSON();
  const out: Record<string, number> = {};
  for (const [peer, counter] of json.entries()) {
    const k = String(peer);
    const num = typeof counter === "number" ? counter : Number(counter);
    if (!Number.isNaN(num)) out[k] = num;
  }
  return out;
}
