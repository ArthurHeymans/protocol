import { VersionVector } from "loro-crdt";
import {
  bytesToHex,
  decodeEloContainer,
  encodeEloContainer,
  parseEloRecordHeader,
  EloRecordKind,
  type EloDeltaHeader,
  type EloSnapshotHeader,
} from "loro-protocol";

interface EloDeltaSpanIndexEntry {
  peerId: Uint8Array;
  start: number;
  end: number;
  keyId: string;
  record: Uint8Array;
}

interface EloSnapshotIndexEntry {
  vv: Map<string, { peerId: Uint8Array; counter: number }>;
  record: Uint8Array;
}

/**
 * In-memory opaque %ELO index. The relay validates plaintext headers but never
 * decrypts ciphertext. Retention keeps the latest valid snapshot and every
 * non-obsolete indexed delta; snapshot receipt never compacts delta history.
 */
export class EloDoc {
  private spansByPeer = new Map<string, EloDeltaSpanIndexEntry[]>();
  private latestSnapshot?: EloSnapshotIndexEntry;
  private verbose: boolean;

  constructor(opts?: { verbose?: boolean }) {
    const env = (
      globalThis as unknown as {
        process?: { env?: Record<string, string | undefined> };
      }
    ).process?.env;
    const envVerbose = env?.ELO_LOG === "1" || env?.ELO_LOG === "true";
    this.verbose = opts?.verbose ?? envVerbose;
  }

  indexBatch(batch: Uint8Array): { ok: true } | { ok: false; error: string } {
    const candidate = this.cloneState();
    const result = candidate.indexBatchInPlace(batch);
    if (result.ok) this.replaceState(candidate);
    return result;
  }

  private indexBatchInPlace(
    batch: Uint8Array
  ): { ok: true } | { ok: false; error: string } {
    let records: Uint8Array[];
    try {
      records = decodeEloContainer(batch);
    } catch (error) {
      return { ok: false, error: this.errorMessage(error) };
    }

    if (records.length === 0) {
      return {
        ok: false,
        error: "Invalid ELO container: expected at least one record",
      };
    }

    for (const record of records) {
      let parsed;
      try {
        parsed = parseEloRecordHeader(record);
      } catch (error) {
        return { ok: false, error: this.errorMessage(error) };
      }

      if (parsed.kind === EloRecordKind.DeltaSpan) {
        const header = parsed.header as EloDeltaHeader;
        const validationError = this.validateCommonHeader(
          "delta span",
          parsed.keyId,
          parsed.iv
        );
        if (validationError) return { ok: false, error: validationError };
        if (!(header.end > header.start)) {
          return {
            ok: false,
            error: "Invalid ELO delta span: end must be > start",
          };
        }
        if (header.peerId.length > 64) {
          return {
            ok: false,
            error: "Invalid ELO delta span: peerId must be ≤ 64 bytes",
          };
        }

        const peerKey = this.peerKeyFromBytes(header.peerId);
        const list = this.spansByPeer.get(peerKey) ?? [];
        const isCovered = list.some(
          entry => entry.start <= header.start && entry.end >= header.end
        );
        if (isCovered) continue;

        const next = list.filter(
          entry => !(entry.start >= header.start && entry.end <= header.end)
        );
        next.push({
          peerId: Uint8Array.from(header.peerId),
          start: header.start,
          end: header.end,
          keyId: parsed.keyId,
          record: Uint8Array.from(record),
        });
        next.sort((a, b) => a.start - b.start || a.end - b.end);
        this.spansByPeer.set(peerKey, next);

        if (this.verbose) {
          console.info("[ELO] indexed-delta", {
            peerId: peerKey,
            start: header.start,
            end: header.end,
            keyId: parsed.keyId,
          });
        }
        continue;
      }

      const header = parsed.header as EloSnapshotHeader;
      const validationError = this.validateCommonHeader(
        "snapshot",
        parsed.keyId,
        parsed.iv
      );
      if (validationError) return { ok: false, error: validationError };
      if (header.vv.length > 1024) {
        return {
          ok: false,
          error:
            "Invalid ELO snapshot: version vector must have ≤ 1024 entries",
        };
      }

      const vv = new Map<string, { peerId: Uint8Array; counter: number }>();
      let previousPeer: Uint8Array | undefined;
      for (const entry of header.vv) {
        if (entry.peerId.length > 64) {
          return {
            ok: false,
            error: "Invalid ELO snapshot: peerId must be ≤ 64 bytes",
          };
        }
        if (
          previousPeer &&
          this.compareBytes(previousPeer, entry.peerId) >= 0
        ) {
          return {
            ok: false,
            error:
              "Invalid ELO snapshot: version vector peers must be strictly sorted",
          };
        }
        previousPeer = entry.peerId;
        vv.set(this.peerKeyFromBytes(entry.peerId), {
          peerId: Uint8Array.from(entry.peerId),
          counter: entry.counter,
        });
      }
      this.latestSnapshot = { vv, record: Uint8Array.from(record) };
      if (this.verbose) {
        console.info("[ELO] retained-snapshot", { keyId: parsed.keyId });
      }
    }

    return { ok: true };
  }

  getVersionBytes(): Uint8Array {
    const counters = new Map<`${number}`, number>();
    const include = (peerId: Uint8Array, counter: number) => {
      const peer = this.canonicalLoroPeer(peerId);
      if (peer === undefined || counter <= 0 || counter > 0x7fff_ffff) return;
      counters.set(peer, Math.max(counters.get(peer) ?? 0, counter));
    };

    for (const spans of this.spansByPeer.values()) {
      for (const span of spans) include(span.peerId, span.end);
    }
    for (const entry of this.latestSnapshot?.vv.values() ?? []) {
      include(entry.peerId, entry.counter);
    }
    if (counters.size === 0) return new Uint8Array();
    return new VersionVector(counters).encode();
  }

  selectBackfillBatches(requesterVersion: Uint8Array): Uint8Array[] {
    const requester = this.decodeRequesterVersion(requesterVersion);
    const records: Uint8Array[] = [];
    const effective = new Map<string, number>();

    for (const [peerKey, spans] of this.spansByPeer) {
      const peerId = spans[0]?.peerId;
      if (peerId)
        effective.set(peerKey, this.requesterCounter(requester, peerId));
    }

    if (this.latestSnapshot) {
      const requesterHasVersion =
        requesterVersion.length > 0 && requester !== undefined;
      const requesterCoversSnapshot =
        requesterHasVersion &&
        [...this.latestSnapshot.vv.values()].every(
          entry =>
            this.requesterCounter(requester, entry.peerId) >= entry.counter
        );
      if (!requesterCoversSnapshot) {
        records.push(this.latestSnapshot.record);
        for (const [peerKey, entry] of this.latestSnapshot.vv) {
          effective.set(
            peerKey,
            Math.max(effective.get(peerKey) ?? 0, entry.counter)
          );
        }
      }
    }

    for (const [peerKey, spans] of this.sortedPeerEntries()) {
      const known = effective.get(peerKey) ?? 0;
      for (const span of spans) {
        if (span.end > known) records.push(span.record);
      }
    }

    if (records.length === 0) return [];
    if (this.verbose) {
      console.info("[ELO] select-backfill", { recordCount: records.length });
    }
    const batches: Uint8Array[] = [];
    let current: Uint8Array[] = [];
    let currentPayloadBytes = 0;
    for (const record of records) {
      const recordBytes = this.uleb128Length(record.length) + record.length;
      const candidateBytes =
        this.uleb128Length(current.length + 1) +
        currentPayloadBytes +
        recordBytes;
      if (current.length > 0 && candidateBytes > 240 * 1024) {
        batches.push(encodeEloContainer(current));
        current = [record];
        currentPayloadBytes = recordBytes;
      } else {
        current.push(record);
        currentPayloadBytes += recordBytes;
      }
    }
    if (current.length > 0) batches.push(encodeEloContainer(current));
    return batches;
  }

  reset(): void {
    this.spansByPeer.clear();
    this.latestSnapshot = undefined;
  }

  loadFromEncodedState(
    data: Uint8Array
  ): { ok: true } | { ok: false; error: string } {
    const candidate = new EloDoc({ verbose: this.verbose });
    const result = data.length
      ? candidate.indexBatchInPlace(data)
      : ({ ok: true } as const);
    if (result.ok) this.replaceState(candidate);
    return result;
  }

  exportIndexedRecords(): Uint8Array {
    const records: Uint8Array[] = [];
    if (this.latestSnapshot) records.push(this.latestSnapshot.record);
    for (const [, spans] of this.sortedPeerEntries()) {
      for (const entry of spans) records.push(entry.record);
    }
    return records.length === 0
      ? new Uint8Array()
      : encodeEloContainer(records);
  }

  private cloneState(): EloDoc {
    const clone = new EloDoc({ verbose: this.verbose });
    clone.spansByPeer = new Map(
      [...this.spansByPeer].map(([peer, spans]) => [peer, spans.slice()])
    );
    clone.latestSnapshot = this.latestSnapshot;
    return clone;
  }

  private replaceState(source: EloDoc): void {
    this.spansByPeer = source.spansByPeer;
    this.latestSnapshot = source.latestSnapshot;
  }

  private sortedPeerEntries(): Array<[string, EloDeltaSpanIndexEntry[]]> {
    return [...this.spansByPeer.entries()].sort(([, left], [, right]) =>
      this.compareBytes(left[0]!.peerId, right[0]!.peerId)
    );
  }

  private decodeRequesterVersion(
    version: Uint8Array
  ): VersionVector | undefined {
    if (!version.length) return undefined;
    try {
      return VersionVector.decode(version);
    } catch {
      return undefined;
    }
  }

  private requesterCounter(
    requester: VersionVector | undefined,
    peerId: Uint8Array
  ): number {
    const peer = this.canonicalLoroPeer(peerId);
    if (!requester || peer === undefined) return 0;
    return Number(requester.get(peer) ?? 0);
  }

  private canonicalLoroPeer(peerId: Uint8Array): `${number}` | undefined {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(peerId);
    } catch {
      return undefined;
    }
    if (!/^(0|[1-9]\d*)$/.test(text)) return undefined;
    try {
      if (BigInt(text) > 0xffff_ffff_ffff_ffffn) return undefined;
    } catch {
      return undefined;
    }
    return text as `${number}`;
  }

  private peerKeyFromBytes(peerId: Uint8Array): string {
    return bytesToHex(peerId);
  }

  private validateCommonHeader(
    kind: "delta span" | "snapshot",
    keyId: string,
    iv: Uint8Array
  ): string | undefined {
    const label = kind === "snapshot" ? "snapshot" : "delta span";
    if (iv.length !== 12) {
      return `Invalid ELO ${label}: IV must be 12 bytes`;
    }
    if (new TextEncoder().encode(keyId).length > 64) {
      return `Invalid ELO ${label}: keyId must be ≤ 64 bytes`;
    }
    return undefined;
  }

  private compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index++) {
      const difference = (a[index] ?? 0) - (b[index] ?? 0);
      if (difference !== 0) return difference;
    }
    return a.length - b.length;
  }

  private uleb128Length(value: number): number {
    let length = 1;
    while (value >= 128) {
      value = Math.floor(value / 128);
      length++;
    }
    return length;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
