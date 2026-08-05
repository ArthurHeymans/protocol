import { describe, it, expect } from "vitest";
import {
  aesGcmDecrypt,
  decodeEloContainer,
  decodeEloDeltaPlaintext,
  encodeEloContainer,
  encodeEloDeltaPlaintext,
  EloRecordKind,
  encryptDeltaSpan,
  encryptSnapshot,
  importAesGcmKey,
  parseEloRecordHeader,
  randomIv12,
} from "../src/e2ee";
import { BytesWriter } from "../src/bytes";
import { bytesToHex, hexToBytes } from "../src/protocol";

describe("%ELO canonical DeltaSpan plaintext", () => {
  it("round trips zero, one, and multiple blobs", () => {
    for (const blobs of [
      [],
      [new Uint8Array([1, 2])],
      [new Uint8Array(), new Uint8Array([3]), new Uint8Array([4, 5])],
    ]) {
      expect(decodeEloDeltaPlaintext(encodeEloDeltaPlaintext(blobs))).toEqual(
        blobs
      );
    }
  });

  it("rejects truncation, trailing bytes, and configured bounds", () => {
    expect(() => decodeEloDeltaPlaintext(new Uint8Array([1]))).toThrow(
      "out of bounds"
    );
    expect(() => decodeEloDeltaPlaintext(new Uint8Array([0, 1]))).toThrow(
      "trailing bytes"
    );
    expect(() =>
      encodeEloDeltaPlaintext([new Uint8Array(), new Uint8Array()], {
        maxBlobs: 1,
      })
    ).toThrow("blob count");
    expect(() =>
      decodeEloDeltaPlaintext(new Uint8Array([2, 0, 0]), { maxBlobs: 1 })
    ).toThrow("blob count");
    expect(() =>
      encodeEloDeltaPlaintext([new Uint8Array(8)], { maxBytes: 2 })
    ).toThrow("byte limit");
    expect(() =>
      decodeEloDeltaPlaintext(new Uint8Array([0, 1]), { maxBytes: 1 })
    ).toThrow("byte limit");
    expect(() => encodeEloDeltaPlaintext([], { maxBytes: 0 })).toThrow(
      "byte limit"
    );
  });
});

describe("%ELO container codec", () => {
  it("encodes and decodes container", () => {
    const records = [new Uint8Array([1, 2, 3]), new Uint8Array([4])];
    const bytes = encodeEloContainer(records);
    const out = decodeEloContainer(bytes);
    expect(out.length).toBe(2);
    const first = out[0];
    const second = out[1];
    if (!first || !second) throw new Error("Expected two decoded records");
    expect(Array.from(first)).toEqual([1, 2, 3]);
    expect(Array.from(second)).toEqual([4]);
  });

  it("rejects an empty container", () => {
    expect(() => decodeEloContainer(encodeEloContainer([]))).toThrow(
      "at least one record"
    );
  });
});

describe("%ELO record header parsing", () => {
  it("parses DeltaSpan header and preserves exact header bytes as AAD", async () => {
    const key = hexToBytes(
      "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const peerId = hexToBytes("0x01020304");
    const iv = hexToBytes("0x86bcad09d5e7e3d70503a57e");
    const plaintext = hexToBytes("0x01026869");
    const meta = { peerId, start: 1, end: 3, keyId: "k1", iv };
    const { record, headerBytes } = await encryptDeltaSpan(
      plaintext,
      meta,
      key
    );
    const parsed = parseEloRecordHeader(record);
    expect(parsed.kind).toBe(EloRecordKind.DeltaSpan);
    expect(bytesToHex(parsed.headerBytes)).toEqual(bytesToHex(headerBytes));
    expect(bytesToHex(parsed.iv)).toEqual(bytesToHex(iv));
    expect(parsed.header.kind).toBe(EloRecordKind.DeltaSpan);
    const h = parsed.header;
    if (h.kind === EloRecordKind.DeltaSpan) {
      expect(bytesToHex(h.peerId)).toEqual(bytesToHex(peerId));
      expect(h.start).toBe(1);
      expect(h.end).toBe(3);
      expect(h.keyId).toBe("k1");
    }
  });
});

describe("%ELO AES-GCM normative vector (DeltaSpan)", () => {
  it("matches ct for known key/iv/aad", async () => {
    // From protocol-e2ee.md
    const key = hexToBytes(
      "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const peerId = hexToBytes("0x01020304");
    const iv = hexToBytes("0x86bcad09d5e7e3d70503a57e");
    const plaintext = hexToBytes("0x01026869"); // varUint 1, varBytes("hi")
    const meta = { peerId, start: 1, end: 3, keyId: "k1", iv };

    const { record } = await encryptDeltaSpan(plaintext, meta, key);
    const parsed = parseEloRecordHeader(record);
    const ctHex = bytesToHex(parsed.ct);
    expect(ctHex).toBe(
      // ciphertext || tag (16B)
      "0x6930a8fbe96cc5f30b67f4bc7f53262e01b62852"
    );
  });
});

describe("%ELO AES-GCM hardening", () => {
  const keyBytes = hexToBytes(
    "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  const iv = hexToBytes("0x86bcad09d5e7e3d70503a57e");
  const plaintext = encodeEloDeltaPlaintext([new Uint8Array([1, 2, 3])]);
  const meta = {
    peerId: hexToBytes("0x01020304"),
    start: 1,
    end: 3,
    keyId: "k1",
    iv,
  };

  it("accepts a real CryptoKey and decrypts a round trip", async () => {
    const cryptoKey = await importAesGcmKey(keyBytes);
    const { record } = await encryptDeltaSpan(plaintext, meta, cryptoKey);
    const parsed = parseEloRecordHeader(record);
    await expect(
      aesGcmDecrypt(cryptoKey, parsed.iv, parsed.ct, parsed.aad)
    ).resolves.toEqual(plaintext);
  });

  it("generates distinct production IVs and rejects invalid IV lengths", async () => {
    expect(randomIv12()).not.toEqual(randomIv12());
    expect(() => randomIv12()).not.toThrow();
    await expect(
      encryptDeltaSpan(plaintext, { ...meta, iv: new Uint8Array(11) }, keyBytes)
    ).rejects.toThrow("IV must be 12 bytes");
  });

  it("rejects tampered headers, IVs, ciphertext, tags, and truncated tags", async () => {
    const { record } = await encryptDeltaSpan(plaintext, meta, keyBytes);
    const parsed = parseEloRecordHeader(record);

    const mutations = [
      (() => {
        const value = record.slice();
        value[2] ^= 1;
        return value;
      })(),
      (() => {
        const value = record.slice();
        value[parsed.headerBytes.length - 1] ^= 1;
        return value;
      })(),
      (() => {
        const value = record.slice();
        value[value.length - 17] ^= 1;
        return value;
      })(),
      (() => {
        const value = record.slice();
        value[value.length - 1] ^= 1;
        return value;
      })(),
    ];
    for (const mutation of mutations) {
      const tampered = parseEloRecordHeader(mutation);
      await expect(
        aesGcmDecrypt(keyBytes, tampered.iv, tampered.ct, tampered.aad)
      ).rejects.toThrow();
    }

    const truncated = new BytesWriter();
    truncated.pushBytes(parsed.headerBytes);
    truncated.pushVarBytes(parsed.ct.subarray(0, 15));
    expect(() => parseEloRecordHeader(truncated.finalize())).toThrow(
      "shorter than the AES-GCM tag"
    );
  });
});

describe("%ELO Snapshot header vv sorting", () => {
  it("sorts vv by peerId bytes ascending during encoding", async () => {
    const key = hexToBytes(
      "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const iv = hexToBytes("0x0102030405060708090a0b0c");
    const plaintext = new Uint8Array([0x00]); // dummy snapshot payload
    const vvUnsorted = [
      { peerId: hexToBytes("0x02"), counter: 5 },
      { peerId: hexToBytes("0x01ff"), counter: 9 },
      { peerId: hexToBytes("0x01"), counter: 7 },
    ];
    const { record } = await encryptSnapshot(
      plaintext,
      { vv: vvUnsorted, keyId: "k1", iv },
      key
    );
    const parsed = parseEloRecordHeader(record);
    expect(parsed.kind).toBe(EloRecordKind.Snapshot);
    const hdr = parsed.header;
    if (hdr.kind === EloRecordKind.Snapshot) {
      // Expected lexicographic order: 0x01, 0x01ff, 0x02
      const order = hdr.vv.map(e => bytesToHex(e.peerId));
      expect(order).toEqual(["0x01", "0x01ff", "0x02"]);
    }
  });
});
