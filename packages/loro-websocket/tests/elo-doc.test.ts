import { describe, expect, it } from "vitest";
import { VersionVector } from "loro-crdt";
import {
  BytesWriter,
  decodeEloContainer,
  encodeEloContainer,
} from "loro-protocol";
import { EloDoc } from "../src/server/elo-doc";

describe("EloDoc opaque retention", () => {
  it("preserves raw peer identity and exports deterministic peer/span order", () => {
    const asciiFf = deltaRecord(new Uint8Array([0x66, 0x66]), 3, 4, 1);
    const opaqueFf = deltaRecord(new Uint8Array([0xff]), 0, 1, 2);
    const earlierAscii = deltaRecord(new Uint8Array([0x66, 0x66]), 1, 2, 3);
    const doc = new EloDoc();

    expect(
      doc.indexBatch(encodeEloContainer([opaqueFf, asciiFf, earlierAscii]))
    ).toEqual({ ok: true });
    expect(decodeEloContainer(doc.exportIndexedRecords())).toEqual([
      earlierAscii,
      asciiFf,
      opaqueFf,
    ]);
  });

  it("replaces covered spans independently of key and retains partial overlaps", () => {
    const old = deltaRecord(bytes("7"), 1, 2, 1, "old-key");
    const covering = deltaRecord(bytes("7"), 0, 3, 2, "new-key");
    const stale = deltaRecord(bytes("7"), 1, 2, 3, "third-key");
    const partial = deltaRecord(bytes("7"), 2, 4, 4, "partial-key");
    const doc = new EloDoc();

    expect(doc.indexBatch(encodeEloContainer([old]))).toEqual({ ok: true });
    expect(doc.indexBatch(encodeEloContainer([covering]))).toEqual({
      ok: true,
    });
    expect(doc.indexBatch(encodeEloContainer([stale, partial]))).toEqual({
      ok: true,
    });
    expect(decodeEloContainer(doc.exportIndexedRecords())).toEqual([
      covering,
      partial,
    ]);
  });

  it("retains only the latest snapshot without deleting delta coverage", () => {
    const firstSnapshot = snapshotRecord([[bytes("7"), 1]], 1);
    const latestSnapshot = snapshotRecord([[bytes("7"), 2]], 2);
    const covered = deltaRecord(bytes("7"), 0, 2, 3);
    const later = deltaRecord(bytes("7"), 2, 3, 4);
    const doc = new EloDoc();

    expect(
      doc.indexBatch(
        encodeEloContainer([firstSnapshot, covered, latestSnapshot, later])
      )
    ).toEqual({ ok: true });
    expect(decodeEloContainer(doc.exportIndexedRecords())).toEqual([
      latestSnapshot,
      covered,
      later,
    ]);
    expect(backfillRecords(doc, new Uint8Array())).toEqual([
      latestSnapshot,
      later,
    ]);

    const requester = new VersionVector(new Map([["7", 3]])).encode();
    expect(doc.selectBackfillBatches(requester)).toEqual([]);
  });

  it("restores the delta index and filtered snapshot-first backfill", () => {
    const snapshot = snapshotRecord([[bytes("7"), 2]], 1);
    const covered = deltaRecord(bytes("7"), 0, 2, 2);
    const later = deltaRecord(bytes("7"), 2, 3, 3);
    const saved = encodeEloContainer([snapshot, covered, later]);
    const restored = new EloDoc();

    expect(restored.loadFromEncodedState(saved)).toEqual({ ok: true });
    expect(restored.exportIndexedRecords()).toEqual(saved);
    expect(backfillRecords(restored, new Uint8Array())).toEqual([
      snapshot,
      later,
    ]);
  });

  it("uses only canonical decimal peer bytes in Loro version vectors", () => {
    const canonical = deltaRecord(bytes("7"), 0, 2, 1);
    const noncanonical = deltaRecord(bytes("07"), 0, 9, 2);
    const invalidUtf8 = deltaRecord(new Uint8Array([0xff]), 0, 10, 3);
    const doc = new EloDoc();

    expect(
      doc.indexBatch(encodeEloContainer([noncanonical, invalidUtf8, canonical]))
    ).toEqual({ ok: true });
    const version = VersionVector.decode(doc.getVersionBytes());
    expect(Number(version.get("7"))).toBe(2);
    expect([...version.toJSON().entries()]).toHaveLength(1);
  });

  it("rejects malformed persisted headers without retaining partial state", () => {
    const valid = deltaRecord(bytes("7"), 0, 1, 1);
    const invalidIv = deltaRecord(bytes("8"), 0, 1, 2, "key", 11);
    const unsortedSnapshot = snapshotRecord(
      [
        [bytes("8"), 1],
        [bytes("7"), 1],
      ],
      3
    );
    const doc = new EloDoc();

    expect(
      doc.loadFromEncodedState(encodeEloContainer([valid, invalidIv])).ok
    ).toBe(false);
    expect(doc.exportIndexedRecords()).toEqual(new Uint8Array());
    expect(
      doc.loadFromEncodedState(encodeEloContainer([unsortedSnapshot])).ok
    ).toBe(false);
    expect(
      doc.loadFromEncodedState(encodeEloContainer([malformedKeyRecord()])).ok
    ).toBe(false);
    expect(
      doc.loadFromEncodedState(
        encodeEloContainer([oversizedSnapshotVectorRecord()])
      ).ok
    ).toBe(false);
    expect(doc.loadFromEncodedState(new Uint8Array([0xff])).ok).toBe(false);
  });

  it("rejects empty ELO containers without changing retained state", () => {
    const retained = deltaRecord(bytes("7"), 0, 1, 1);
    const doc = new EloDoc();
    expect(doc.indexBatch(encodeEloContainer([retained]))).toEqual({
      ok: true,
    });

    expect(doc.indexBatch(encodeEloContainer([])).ok).toBe(false);
    expect(decodeEloContainer(doc.exportIndexedRecords())).toEqual([retained]);
  });

  it("chunks large retained backfill into bounded containers", () => {
    const records = [
      deltaRecord(bytes("1"), 0, 1, 1, "key", 12, 100 * 1024),
      deltaRecord(bytes("2"), 0, 1, 2, "key", 12, 100 * 1024),
      deltaRecord(bytes("3"), 0, 1, 3, "key", 12, 100 * 1024),
    ];
    const doc = new EloDoc();
    expect(doc.indexBatch(encodeEloContainer(records))).toEqual({ ok: true });

    const batches = doc.selectBackfillBatches(new Uint8Array());
    expect(batches.length).toBeGreaterThan(1);
    expect(batches.every(batch => batch.length <= 240 * 1024)).toBe(true);
    expect(batches.flatMap(batch => decodeEloContainer(batch))).toEqual(
      records
    );
  });

  it("omits counters that cannot be represented by a Loro version vector", () => {
    const doc = new EloDoc();
    expect(
      doc.indexBatch(
        encodeEloContainer([deltaRecord(bytes("7"), 0, 0xffff_ffff, 1)])
      )
    ).toEqual({ ok: true });
    expect(doc.getVersionBytes()).toEqual(new Uint8Array());
  });
});

function backfillRecords(doc: EloDoc, version: Uint8Array): Uint8Array[] {
  const batches = doc.selectBackfillBatches(version);
  return batches.flatMap(batch => decodeEloContainer(batch));
}

function deltaRecord(
  peerId: Uint8Array,
  start: number,
  end: number,
  marker: number,
  keyId = "key-1",
  ivLength = 12,
  ciphertextLength = 16
): Uint8Array {
  const writer = new BytesWriter();
  writer.pushByte(0x00);
  writer.pushVarBytes(peerId);
  writer.pushUleb128(start);
  writer.pushUleb128(end);
  writer.pushVarString(keyId);
  writer.pushVarBytes(new Uint8Array(ivLength).fill(marker));
  writer.pushVarBytes(new Uint8Array(ciphertextLength).fill(marker));
  return writer.finalize();
}

function malformedKeyRecord(): Uint8Array {
  const writer = new BytesWriter();
  writer.pushByte(0x00);
  writer.pushVarBytes(bytes("7"));
  writer.pushUleb128(0);
  writer.pushUleb128(1);
  writer.pushVarBytes(new Uint8Array([0xff]));
  writer.pushVarBytes(new Uint8Array(12));
  writer.pushVarBytes(new Uint8Array([1]));
  return writer.finalize();
}

function oversizedSnapshotVectorRecord(): Uint8Array {
  const writer = new BytesWriter();
  writer.pushByte(0x01);
  writer.pushUleb128(1025);
  return writer.finalize();
}

function snapshotRecord(
  vv: Array<[Uint8Array, number]>,
  marker: number
): Uint8Array {
  const writer = new BytesWriter();
  writer.pushByte(0x01);
  writer.pushUleb128(vv.length);
  for (const [peerId, counter] of vv) {
    writer.pushVarBytes(peerId);
    writer.pushUleb128(counter);
  }
  writer.pushVarString("key-1");
  writer.pushVarBytes(new Uint8Array(12).fill(marker));
  writer.pushVarBytes(new Uint8Array(16).fill(marker));
  return writer.finalize();
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
