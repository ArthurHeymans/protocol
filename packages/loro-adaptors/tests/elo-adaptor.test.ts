import { describe, it, expect, vi, beforeEach } from "vitest";
import { LoroDoc } from "loro-crdt";
import {
  EloAdaptor,
  EloKeyring,
  type EloAdaptorError,
} from "../src/loro";
import { CrdtType, MessageType } from "loro-protocol";
import { parseEloRecordHeader, decodeEloContainer } from "loro-protocol";
import { encryptDeltaSpan, encodeEloContainer } from "loro-protocol";

const KEY_HEX =
  "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2)
    out[i / 2] = parseInt(s.slice(i, i + 2), 16);
  return out;
}

describe("EloAdaptor — snapshot join", () => {
  let doc: LoroDoc;
  let adaptor: EloAdaptor;
  const key = hexToBytes(KEY_HEX);
  const fixedIv = hexToBytes("0x0102030405060708090a0b0c");

  beforeEach(() => {
    doc = new LoroDoc();
    adaptor = new EloAdaptor(doc, {
      getPrivateKey: async () => ({ keyId: "k1", key }),
      ivFactory: () => fixedIv,
    });
  });

  it("sends a snapshot container when server has no version", async () => {
    const mockSend = vi.fn();
    adaptor.setCtx({
      send: mockSend,
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    await adaptor.handleJoinOk({
      type: MessageType.JoinResponseOk,
      crdt: CrdtType.Elo,
      roomId: "room",
      permission: "write",
      version: new Uint8Array(),
    });

    expect(mockSend).toHaveBeenCalledTimes(1);
    const [[updates]] = mockSend.mock.calls as [Uint8Array[]][];
    expect(updates.length).toBe(1);
    const [container] = updates;
    const records = decodeEloContainer(container);
    expect(records.length).toBe(1);
    const record = records[0];
    if (!record) throw new Error("Expected an ELO record to be emitted");
    const parsed = parseEloRecordHeader(record);
    expect(parsed.kind).toBe(0x01); // Snapshot
    expect(parsed.keyId).toBe("k1");
    expect(parsed.iv.length).toBe(12);
  });
});

describe("EloAdaptor — apply snapshot update", () => {
  it("applies a snapshot container and updates the doc", async () => {
    const key = hexToBytes(KEY_HEX);
    // Create a source doc with content
    const source = new LoroDoc();
    source.getText("test").insert(0, "hello");
    source.commit();
    const plaintext = source.export({ mode: "snapshot" });

    const adaptorDoc = new LoroDoc();
    const adaptor = new EloAdaptor(adaptorDoc, {
      getPrivateKey: async () => ({ keyId: "k1", key }),
      ivFactory: () => hexToBytes("0x0102030405060708090a0b0c"),
    });
    adaptor.setCtx({
      send: vi.fn(),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    // Build a single snapshot record container using the same helpers the adaptor uses
    const { encryptSnapshot, encodeEloContainer } = await import(
      "loro-protocol"
    );
    const { record } = await encryptSnapshot(
      plaintext,
      { vv: [], keyId: "k1", iv: hexToBytes("0x0102030405060708090a0b0c") },
      key
    );
    const container = encodeEloContainer([record]);

    // Apply to adaptor doc
    adaptor.applyUpdate([container]);
    // Wait briefly for async decrypt/import to complete
    await new Promise(res => setTimeout(res, 10));
    expect(adaptorDoc.getText("test").toString()).toBe("hello");
  });
});

describe("EloAdaptor — key management", () => {
  it("selects the parsed key ID and classifies a known wrong key", async () => {
    const key1 = hexToBytes(KEY_HEX);
    const key2 = new Uint8Array(32).fill(0x22);
    const wrongKey2 = new Uint8Array(32).fill(0x33);
    const keyring = new EloKeyring([
      { keyId: "k1", key: key1 },
      { keyId: "k2", key: wrongKey2 },
    ], "k1");
    const errors: EloAdaptorError[] = [];
    const destination = new LoroDoc();
    const adaptor = new EloAdaptor(destination, {
      keyResolver: keyring,
      onEloError: error => errors.push(error),
    });
    adaptor.setCtx({
      send: vi.fn(),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    const source = new LoroDoc();
    source.getText("test").insert(0, "rotated");
    source.commit();
    const { record } = await encryptDeltaSpan(
      source.export({ mode: "update" }),
      {
        peerId: new TextEncoder().encode("1"),
        start: 0,
        end: 1,
        keyId: "k2",
        iv: hexToBytes("0x111111111111111111111111"),
      },
      key2
    );

    adaptor.applyUpdate([encodeEloContainer([record])]);
    await adaptor.retryPendingEncryptedRecords();

    expect(destination.getText("test").toString()).toBe("");
    expect(errors.map(error => error.kind)).toEqual(["decrypt_failed"]);
    expect(errors[0]?.keyId).toBe("k2");
  });

  it("rejects resolver key-ID mismatches without attempting decryption", async () => {
    const key = hexToBytes(KEY_HEX);
    const errors: EloAdaptorError[] = [];
    const source = new LoroDoc();
    source.getText("test").insert(0, "secret");
    source.commit();
    const { record } = await encryptDeltaSpan(
      source.export({ mode: "update" }),
      {
        peerId: new TextEncoder().encode("1"),
        start: 0,
        end: 1,
        keyId: "requested",
        iv: new Uint8Array(12).fill(9),
      },
      key
    );
    const adaptor = new EloAdaptor({
      keyResolver: {
        resolveKey: async () => ({ keyId: "wrong", key }),
      },
      onEloError: error => errors.push(error),
    });

    adaptor.applyUpdate([encodeEloContainer([record])]);
    await adaptor.retryPendingEncryptedRecords();

    expect(adaptor.pendingEncryptedRecordCount).toBe(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.kind).toBe("unknown_key");
    expect(errors[0]?.cause.message).toContain(
      "returned key ID wrong for requested ID requested"
    );
  });

  it("deduplicates, bounds, and retries records whose key is unknown", async () => {
    const knownKey = hexToBytes(KEY_HEX);
    const missingKey = new Uint8Array(32).fill(0x44);
    const keyring = new EloKeyring([{ keyId: "k1", key: knownKey }], "k1");
    const errors: EloAdaptorError[] = [];
    const destination = new LoroDoc();
    const adaptor = new EloAdaptor(destination, {
      keyResolver: keyring,
      pendingEncryptedRecords: { maxRecords: 1, maxBytes: 1024 * 1024 },
      onEloError: error => errors.push(error),
    });
    adaptor.setCtx({
      send: vi.fn(),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    const makeRecord = async (text: string, ivByte: number) => {
      const source = new LoroDoc();
      source.getText("test").insert(0, text);
      source.commit();
      return (
        await encryptDeltaSpan(
          source.export({ mode: "update" }),
          {
            peerId: new TextEncoder().encode(String(ivByte)),
            start: 0,
            end: 1,
            keyId: "k2",
            iv: new Uint8Array(12).fill(ivByte),
          },
          missingKey
        )
      ).record;
    };
    const evicted = await makeRecord("old", 1);
    const retained = await makeRecord("new", 2);

    adaptor.applyUpdate([
      encodeEloContainer([evicted, evicted, retained]),
    ]);
    await adaptor.retryPendingEncryptedRecords();
    expect(adaptor.pendingEncryptedRecordCount).toBe(1);
    expect(errors.filter(error => error.kind === "unknown_key")).toHaveLength(2);
    expect(errors.some(error => error.kind === "pending_evicted")).toBe(true);

    keyring.addKey("k2", missingKey);
    const result = await adaptor.retryPendingEncryptedRecords();
    expect(result).toEqual({ attempted: 1, imported: 1, remaining: 0 });
    expect(destination.getText("test").toString()).toBe("new");
  });

  it("retries retained records once in FIFO order", async () => {
    const key2 = new Uint8Array(32).fill(2);
    const key3 = new Uint8Array(32).fill(3);
    const keyring = new EloKeyring();
    const resolvedIds: Array<string | undefined> = [];
    const adaptor = new EloAdaptor({
      keyResolver: {
        resolveKey: async keyId => {
          resolvedIds.push(keyId);
          return keyring.resolveKey(keyId);
        },
      },
    });
    const makeRecord = async (keyId: string, key: Uint8Array, ivByte: number) => {
      const source = new LoroDoc();
      source.getText("test").insert(0, keyId);
      source.commit();
      return (
        await encryptDeltaSpan(
          source.export({ mode: "update" }),
          {
            peerId: new TextEncoder().encode(String(ivByte)),
            start: 0,
            end: 1,
            keyId,
            iv: new Uint8Array(12).fill(ivByte),
          },
          key
        )
      ).record;
    };
    const record2 = await makeRecord("k2", key2, 2);
    const record3 = await makeRecord("k3", key3, 3);
    adaptor.applyUpdate([encodeEloContainer([record2, record3])]);
    await adaptor.retryPendingEncryptedRecords();
    resolvedIds.splice(0);

    keyring.addKey("k2", key2);
    keyring.addKey("k3", key3);
    const [firstRetry, concurrentRetry] = await Promise.all([
      adaptor.retryPendingEncryptedRecords(),
      adaptor.retryPendingEncryptedRecords(),
    ]);
    const secondRetry = await adaptor.retryPendingEncryptedRecords();

    expect(resolvedIds).toEqual(["k2", "k3"]);
    expect(firstRetry).toEqual({ attempted: 2, imported: 2, remaining: 0 });
    expect(concurrentRetry).toEqual(firstRetry);
    expect(secondRetry).toEqual({ attempted: 0, imported: 0, remaining: 0 });
  });

  it("rotates future writes and publishes a new-key snapshot for bootstrap", async () => {
    const key1 = hexToBytes(KEY_HEX);
    const key2 = new Uint8Array(32).fill(0x55);
    const keyring = new EloKeyring([{ keyId: "k1", key: key1 }], "k1");
    const source = new LoroDoc();
    const adaptor = new EloAdaptor(source, {
      keyResolver: keyring,
      ivFactory: (() => {
        let value = 0;
        return () => new Uint8Array(12).fill(++value);
      })(),
    });
    const sent: Uint8Array[] = [];
    adaptor.setCtx({
      send: updates => sent.push(...updates),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    source.getText("test").insert(0, "before");
    source.commit();
    await vi.waitFor(() => expect(sent.length).toBe(1));
    expect(parseEloRecordHeader(decodeEloContainer(sent[0]!)[0]!).keyId).toBe("k1");

    keyring.addKey("k2", key2);
    keyring.setActiveKey("k2");
    source.getText("test").insert(6, " after");
    source.commit();
    await vi.waitFor(() => expect(sent.length).toBe(2));
    expect(parseEloRecordHeader(decodeEloContainer(sent[1]!)[0]!).keyId).toBe("k2");

    await adaptor.publishSnapshot();
    const snapshot = sent.at(-1)!;
    const snapshotHeader = parseEloRecordHeader(decodeEloContainer(snapshot)[0]!);
    expect(snapshotHeader.kind).toBe(1);
    expect(snapshotHeader.keyId).toBe("k2");

    const restarted = new LoroDoc();
    const newKeyOnlyAdaptor = new EloAdaptor(restarted, {
      keyResolver: new EloKeyring([{ keyId: "k2", key: key2 }], "k2"),
    });
    newKeyOnlyAdaptor.setCtx({
      send: vi.fn(),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });
    newKeyOnlyAdaptor.applyUpdate([snapshot]);
    await newKeyOnlyAdaptor.retryPendingEncryptedRecords();
    expect(restarted.getText("test").toString()).toBe("before after");
  });

  it("serializes delayed outbound resolution before snapshot publication", async () => {
    const key = hexToBytes(KEY_HEX);
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>(resolve => {
      releaseFirst = resolve;
    });
    let calls = 0;
    const source = new LoroDoc();
    const sent: Uint8Array[] = [];
    const adaptor = new EloAdaptor(source, {
      keyResolver: {
        resolveKey: async () => {
          calls++;
          if (calls === 1) await firstGate;
          return { keyId: "k1", key };
        },
      },
      ivFactory: (() => {
        let value = 0;
        return () => new Uint8Array(12).fill(++value);
      })(),
    });
    adaptor.setCtx({
      send: updates => sent.push(...updates),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    source.getText("test").insert(0, "ordered");
    source.commit();
    const publish = adaptor.publishSnapshot();
    await vi.waitFor(() => expect(calls).toBe(1));
    expect(sent).toHaveLength(0);
    releaseFirst();
    await publish;

    expect(sent).toHaveLength(2);
    expect(
      sent.map(container =>
        parseEloRecordHeader(decodeEloContainer(container)[0]!).kind
      )
    ).toEqual([0, 1]);
  });

  it("rejects conflicting key IDs and protects byte keys from mutation", async () => {
    const original = new Uint8Array(32).fill(7);
    const keyring = new EloKeyring([{ keyId: "k1", key: original }], "k1");
    original.fill(9);

    const resolved = await keyring.resolveKey("k1");
    expect(resolved?.key).toEqual(new Uint8Array(32).fill(7));
    if (!(resolved?.key instanceof Uint8Array)) {
      throw new Error("Expected a byte key");
    }
    resolved.key.fill(3);
    expect((await keyring.resolveKey("k1"))?.key).toEqual(
      new Uint8Array(32).fill(7)
    );
    expect(() => keyring.addKey("k1", new Uint8Array(32).fill(7))).not.toThrow();
    expect(() => keyring.addKey("k1", new Uint8Array(32))).toThrow(
      "already exists"
    );
    expect(
      () => new EloKeyring([{ keyId: "k1", key: original }], "missing")
    ).toThrow("Unknown ELO key ID");
  });

  it("classifies malformed headers before key lookup", async () => {
    const key = hexToBytes(KEY_HEX);
    const errors: EloAdaptorError[] = [];
    const { record } = await encryptDeltaSpan(
      new Uint8Array([1]),
      {
        peerId: new Uint8Array([1]),
        start: 0,
        end: 1,
        keyId: "k1",
        iv: new Uint8Array(12).fill(1),
      },
      key
    );
    const invalidRange = record.slice();
    invalidRange[3] = 1;
    const adaptor = new EloAdaptor({
      keyResolver: new EloKeyring([{ keyId: "k1", key }], "k1"),
      onEloError: error => errors.push(error),
    });
    adaptor.applyUpdate([encodeEloContainer([invalidRange])]);
    await adaptor.retryPendingEncryptedRecords();
    expect(errors.map(error => error.kind)).toEqual(["malformed_record"]);
  });

  it("reports unknown keys even when bounds immediately evict them", async () => {
    const key = hexToBytes(KEY_HEX);
    const missingKey = new Uint8Array(32).fill(4);
    const errors: EloAdaptorError[] = [];
    const decryptErrors = vi.fn();
    const { record } = await encryptDeltaSpan(
      new Uint8Array([1]),
      {
        peerId: new Uint8Array([1]),
        start: 0,
        end: 1,
        keyId: "missing",
        iv: new Uint8Array(12).fill(2),
      },
      missingKey
    );
    const adaptor = new EloAdaptor({
      keyResolver: new EloKeyring([{ keyId: "known", key }], "known"),
      pendingEncryptedRecords: { maxRecords: 0, maxBytes: 0 },
      onEloError: error => errors.push(error),
      onDecryptError: decryptErrors,
    });
    adaptor.applyUpdate([encodeEloContainer([record])]);
    await adaptor.retryPendingEncryptedRecords();

    expect(errors.map(error => error.kind)).toEqual([
      "pending_evicted",
      "unknown_key",
    ]);
    expect(decryptErrors).toHaveBeenCalledTimes(1);
    expect(adaptor.pendingEncryptedRecordCount).toBe(0);
    expect(
      () =>
        new EloAdaptor({
          keyResolver: new EloKeyring(),
          pendingEncryptedRecords: { maxBytes: Number.POSITIVE_INFINITY },
        })
    ).toThrow("non-negative safe integer");
  });

  it("contains throwing error callbacks and rejects repeated IVs", async () => {
    const key = hexToBytes(KEY_HEX);
    const errors: EloAdaptorError[] = [];
    const source = new LoroDoc();
    const sent: Uint8Array[] = [];
    const adaptor = new EloAdaptor(source, {
      keyResolver: new EloKeyring([{ keyId: "k1", key }], "k1"),
      ivFactory: () => new Uint8Array(12).fill(8),
      onEloError: error => {
        errors.push(error);
        throw new Error("callback failure");
      },
    });
    adaptor.setCtx({
      send: updates => sent.push(...updates),
      onJoinFailed: vi.fn(),
      onImportError: () => {
        throw new Error("nested callback failure");
      },
    });

    source.getText("test").insert(0, "one");
    source.commit();
    await vi.waitFor(() => expect(sent).toHaveLength(1));
    source.getText("test").insert(3, " two");
    source.commit();
    await vi.waitFor(() =>
      expect(errors.some(error => error.kind === "encrypt_failed")).toBe(true)
    );
    expect(sent).toHaveLength(1);
  });
});

describe("EloAdaptor — apply delta update", () => {
  it("applies a delta container update and updates the doc", async () => {
    const key = hexToBytes(KEY_HEX);
    // Create source update plaintext via standard update export
    const source = new LoroDoc();
    source.getText("test").insert(0, "hello");
    source.commit();
    const plaintext = source.export({ mode: "update" });

    const adaptorDoc = new LoroDoc();
    const adaptor = new EloAdaptor(adaptorDoc, {
      getPrivateKey: async () => ({ keyId: "k1", key }),
      ivFactory: () => hexToBytes("0x0102030405060708090a0b0c"),
    });
    adaptor.setCtx({
      send: vi.fn(),
      onJoinFailed: vi.fn(),
      onImportError: vi.fn(),
    });

    // Build a single delta record container
    const peerId = new TextEncoder().encode("peer-1");
    const { record } = await encryptDeltaSpan(
      plaintext,
      {
        peerId,
        start: 1,
        end: 2,
        keyId: "k1",
        iv: hexToBytes("0x0102030405060708090a0b0c"),
      },
      key
    );
    const container = encodeEloContainer([record]);

    adaptor.applyUpdate([container]);
    await new Promise(res => setTimeout(res, 10));
    expect(adaptorDoc.getText("test").toString()).toBe("hello");
  });
});
