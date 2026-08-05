import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  CrdtType,
  JoinErrorCode,
  MessageType,
  type DocUpdateFragment,
  type DocUpdateFragmentHeader,
  type JoinError,
} from "loro-protocol";
import * as protocol from "loro-protocol";
import { LoroWebsocketClient } from "./index";

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = FakeWebSocket.CLOSED;
  bufferedAmount = 0;
  binaryType: any = "arraybuffer";
  url: string;
  lastSent: unknown;
  sent: unknown[] = [];
  private listeners = new Map<string, Set<(ev: any) => void>>();

  constructor(url: string) {
    this.url = url;
  }

  addEventListener(type: string, listener: (ev: any) => void) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: (ev: any) => void) {
    const set = this.listeners.get(type);
    set?.delete(listener);
  }

  dispatch(type: string, ev: any) {
    const set = this.listeners.get(type);
    if (!set) return;
    for (const l of Array.from(set)) l(ev);
  }

  send(data: any) {
    if (this.readyState !== FakeWebSocket.OPEN) {
      throw new Error("WebSocket is not open");
    }
    this.lastSent = data;
    this.sent.push(data);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
  }
}

describe("LoroWebsocketClient", () => {
  let originalWebSocket: any;

  beforeEach(() => {
    originalWebSocket = (globalThis as any).WebSocket;
    (globalThis as any).WebSocket = FakeWebSocket as any;
  });

  afterEach(() => {
    (globalThis as any).WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("does not throw when retrying join after closed socket and reports via onError", async () => {
    const onError = vi.fn();
    const client = new LoroWebsocketClient({
      url: "ws://test",
      disablePing: true,
      reconnect: { enabled: false },
      onError,
    });

    const adaptor = {
      crdtType: CrdtType.Loro,
      setCtx: () => {},
      getVersion: () => new Uint8Array([0]),
      getAlternativeVersion: () => new Uint8Array([1]),
      handleJoinOk: async () => {},
      waitForReachingServerVersion: async () => {},
      destroy: () => {},
    } satisfies any;

    const joinError: JoinError = {
      type: MessageType.JoinError,
      code: JoinErrorCode.VersionUnknown,
      message: "",
      crdt: adaptor.crdtType,
      roomId: "room",
    };

    const pending = {
      room: Promise.resolve({} as any),
      resolve: () => {},
      reject: () => {},
      adaptor,
      roomId: "room",
    } satisfies any;

    // Avoid unhandled rejection when the client is destroyed without ever opening.
    (client as any).connectedPromise?.catch(() => {});

    // Force the current socket to a closed state so send will fail.
    (client as any).ws.readyState = FakeWebSocket.CLOSED;

    await expect(
      (client as any).handleJoinError(
        joinError,
        pending,
        adaptor.crdtType + "room"
      )
    ).resolves.not.toThrow();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(((client as any).queuedJoins ?? []).length).toBeGreaterThan(0);
  });

  it("waits for adaptor initialization before activating and flushing backfill", async () => {
    const client = new LoroWebsocketClient({
      url: "ws://test",
      disablePing: true,
      reconnect: { enabled: false },
    });
    const ws = (client as any).ws as FakeWebSocket;
    ws.readyState = FakeWebSocket.OPEN;
    ws.dispatch("open", {});
    let releaseJoin!: () => void;
    const joinGate = new Promise<void>(resolve => {
      releaseJoin = resolve;
    });
    const events: string[] = [];
    const adaptor = {
      crdtType: CrdtType.Loro,
      setCtx: () => {},
      getVersion: () => new Uint8Array(),
      cmpVersion: () => 0 as const,
      handleJoinOk: async () => {
        events.push("join-start");
        await joinGate;
        events.push("join-ready");
      },
      applyUpdate: () => {
        events.push("update");
      },
      waitForReachingServerVersion: async () => {},
      destroy: () => {},
    } satisfies any;

    const joining = client.join({ roomId: "room", crdtAdaptor: adaptor });
    await Promise.resolve();
    await (client as any).handleMessage({
      type: MessageType.JoinResponseOk,
      crdt: CrdtType.Loro,
      roomId: "room",
      permission: "write",
      version: new Uint8Array(),
      extra: new Uint8Array(),
    });
    await Promise.resolve();
    await (client as any).handleMessage({
      type: MessageType.DocUpdate,
      crdt: CrdtType.Loro,
      roomId: "room",
      updates: [new Uint8Array([1])],
      batchId: "0x0101010101010101",
    });

    expect(events).toEqual(["join-start"]);
    expect((client as any).activeRooms.size).toBe(0);
    releaseJoin();
    await joining;
    expect(events).toEqual(["join-start", "join-ready", "update"]);
    client.destroy();
  });

  it("resends a pending initial join that was already written", async () => {
    const client = new LoroWebsocketClient({
      url: "ws://test",
      disablePing: true,
      reconnect: { enabled: false },
    });
    const ws = (client as any).ws as FakeWebSocket;
    ws.readyState = FakeWebSocket.OPEN;
    ws.dispatch("open", {});
    const adaptor = {
      crdtType: CrdtType.Loro,
      setCtx: () => {},
      getVersion: () => new Uint8Array([1]),
      cmpVersion: () => 0 as const,
      handleJoinOk: async () => {},
      applyUpdate: () => {},
      waitForReachingServerVersion: async () => {},
      destroy: () => {},
    } satisfies any;

    void client
      .join({ roomId: "pending", crdtAdaptor: adaptor })
      .catch(() => {});
    await vi.waitFor(() => {
      expect(ws.sent).toHaveLength(1);
    });
    (client as any).retrySentPendingRooms();
    await vi.waitFor(() => {
      expect(ws.sent).toHaveLength(2);
    });
    client.destroy();
  });

  it("bounds fragment headers and rejects duplicate fragment indices", () => {
    const onError = vi.fn();
    const client = new LoroWebsocketClient({
      url: "ws://test",
      disablePing: true,
      reconnect: { enabled: false },
      onError,
      maxFragmentsPerBatch: 2,
      maxFragmentBatchBytes: 4,
    });
    (client as any).connectedPromise?.catch(() => {});
    (client as any).activeRooms.set(CrdtType.Loro + "room", {});

    const header: DocUpdateFragmentHeader = {
      type: MessageType.DocUpdateFragmentHeader,
      crdt: CrdtType.Loro,
      roomId: "room",
      batchId: "0x0101010101010101",
      fragmentCount: 3,
      totalSizeBytes: 3,
    };
    (client as any).handleFragmentHeader(header);
    expect((client as any).fragmentBatches.size).toBe(0);

    header.fragmentCount = 2;
    header.totalSizeBytes = 2;
    (client as any).handleFragmentHeader(header);
    expect((client as any).fragmentBatches.size).toBe(1);

    const fragment: DocUpdateFragment = {
      type: MessageType.DocUpdateFragment,
      crdt: CrdtType.Loro,
      roomId: "room",
      batchId: header.batchId,
      index: 0,
      fragment: new Uint8Array([1]),
    };
    (client as any).handleFragment(fragment);
    (client as any).handleFragment(fragment);

    expect((client as any).fragmentBatches.size).toBe(0);
    expect(onError).toHaveBeenCalledTimes(2);
  });

  it("forwards decode or handler errors to onError instead of crashing", async () => {
    const onError = vi.fn();
    const client = new LoroWebsocketClient({
      url: "ws://test",
      disablePing: true,
      reconnect: { enabled: false },
      onError,
    });

    (client as any).connectedPromise?.catch(() => {});

    vi.spyOn(protocol, "tryDecode").mockImplementation(() => {
      throw new Error("decode failed");
    });

    await (client as any).onSocketMessage((client as any).ws, {
      data: new ArrayBuffer(0),
    } as MessageEvent<ArrayBuffer>);

    expect(onError).toHaveBeenCalledTimes(1);
  });
});
