import { describe, expect, it } from "vitest";
import { BytesReader, BytesWriter } from "../src/bytes";

describe("BytesWriter/BytesReader", () => {
  it("round-trips ULEB128 for typical bounds", () => {
    const values = [
      0,
      1,
      2,
      10,
      127,
      128,
      129,
      255,
      256,
      16383,
      16384,
      0xffff,
      0x1fffff,
      0x0fffffff,
      0x7fffffff,
      0xffff_ffff,
      Number.MAX_SAFE_INTEGER,
    ];

    const w = new BytesWriter();
    for (const n of values) {
      w.pushUleb128(n);
    }
    const buf = w.finalize();

    const r = new BytesReader(buf);
    const out: number[] = [];
    for (let i = 0; i < values.length; i++) {
      out.push(r.readUleb128());
    }
    expect(out).toEqual(values);
    expect(r.remaining).toBe(0);
  });

  it("rejects invalid or unrepresentable ULEB128 values", () => {
    const writer = new BytesWriter();
    expect(() => {
      writer.pushUleb128(-1);
    }).toThrow(/non-negative safe integer/);
    expect(() => {
      writer.pushUleb128(Number.MAX_SAFE_INTEGER + 1);
    }).toThrow(/non-negative safe integer/);

    const overflowingU64 = new Uint8Array([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ]);
    expect(() => new BytesReader(overflowingU64).readUleb128()).toThrow(
      /safe integer range/
    );
  });

  it("round-trips varBytes with empty, small, and large payloads", () => {
    const empty = new Uint8Array([]);
    const small = new Uint8Array([1, 2, 3, 4, 5]);
    const large = new Uint8Array(5000);
    for (let i = 0; i < large.length; i++) large[i] = i & 0xff;

    const w = new BytesWriter();
    w.pushVarBytes(empty);
    w.pushVarBytes(small);
    w.pushVarBytes(large);
    const buf = w.finalize();

    const r = new BytesReader(buf);
    expect([...r.readVarBytes()]).toEqual([...empty]);
    expect([...r.readVarBytes()]).toEqual([...small]);
    expect([...r.readVarBytes()]).toEqual([...large]);
    expect(r.remaining).toBe(0);
  });

  it("round-trips varString including UTF-8", () => {
    const values = [
      "",
      "a",
      "hello world",
      "こんにちは",
      "😀 emojis 🚀🔥",
      "汉字 and mixed ASCII",
    ];

    const w = new BytesWriter();
    for (const s of values) w.pushVarString(s);
    const buf = w.finalize();

    const r = new BytesReader(buf);
    const out: string[] = [];
    for (let i = 0; i < values.length; i++) out.push(r.readVarString());
    expect(out).toEqual(values);
    expect(r.remaining).toBe(0);
  });

  it("rejects malformed UTF-8 varStrings", () => {
    expect(() =>
      new BytesReader(new Uint8Array([1, 0xff])).readVarString()
    ).toThrow();
  });

  it("rejects invalid fixed byte lengths", () => {
    const reader = new BytesReader(new Uint8Array([1, 2]));
    expect(() => reader.readBytes(Number.NaN)).toThrow("out of bounds");
    expect(() => reader.readBytes(0.5)).toThrow("out of bounds");
  });

  it("supports mixed sequence of fields", () => {
    const w = new BytesWriter();
    // Write a sequence: uleb, string, bytes, uleb, string
    w.pushUleb128(128);
    w.pushVarString("mix");
    w.pushVarBytes(new Uint8Array([9, 8, 7]));
    w.pushUleb128(999999);
    w.pushVarString("end");
    const buf = w.finalize();

    const r = new BytesReader(buf);
    expect(r.readUleb128()).toBe(128);
    expect(r.readVarString()).toBe("mix");
    expect([...r.readVarBytes()]).toEqual([9, 8, 7]);
    expect(r.readUleb128()).toBe(999999);
    expect(r.readVarString()).toBe("end");
    expect(r.remaining).toBe(0);
  });
});
