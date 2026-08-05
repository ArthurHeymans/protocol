import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import getPort from "get-port";
import { WebSocket } from "ws";
import { EloAdaptor, EloKeyring } from "loro-adaptors/loro";
import {
  BytesWriter,
  CrdtType,
  decodeEloContainer,
  EloRecordKind,
  encode,
  encodeEloContainer,
  MessageType,
  parseEloRecordHeader,
  tryDecode,
  UpdateStatusCode,
  type ProtocolMessage,
} from "loro-protocol";
import { LoroWebsocketClient } from "../src/client";
import { SimpleServer } from "../src/server/simple-server";

Object.defineProperty(globalThis, "WebSocket", {
  value: WebSocket,
  configurable: true,
  writable: true,
});
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
}

describe("E2E: %ELO persistence", () => {
  const servers: SimpleServer[] = [];

  afterEach(async () => {
    await Promise.all(servers.splice(0).map(server => server.stop()));
  });

  it("awaits opaque save callbacks and restores a late joiner after restart", async () => {
    const stored = new Map<string, Uint8Array>();
    const loadCalls: Array<{ roomId: string; crdt: CrdtType }> = [];
    const saveCalls: Array<{ roomId: string; crdt: CrdtType }> = [];
    let releaseSave!: () => void;
    const saveGate = new Promise<void>(resolve => {
      releaseSave = resolve;
    });
    let notifySaveStarted!: () => void;
    const saveStarted = new Promise<void>(resolve => {
      notifySaveStarted = resolve;
    });

    const firstPort = await getPort();
    const firstServer = new SimpleServer({
      port: firstPort,
      saveInterval: 60_000,
      onLoadDocument: async (roomId, crdt) => {
        loadCalls.push({ roomId, crdt });
        return stored.get(roomId)?.slice() ?? null;
      },
      onSaveDocument: async (roomId, crdt, data) => {
        saveCalls.push({ roomId, crdt });
        stored.set(roomId, data.slice());
        notifySaveStarted();
        await saveGate;
      },
    });
    servers.push(firstServer);
    await firstServer.start();

    const key = new Uint8Array(16);
    key[0] = 42;
    const rotatedKey = new Uint8Array(16);
    rotatedKey[0] = 84;
    const firstClient = new LoroWebsocketClient({
      url: `ws://localhost:${firstPort}`,
      disablePing: true,
    });
    await firstClient.waitConnected();
    const firstKeyring = new EloKeyring([{ keyId: "key-1", key }], "key-1");
    const firstAdaptor = new EloAdaptor({ keyResolver: firstKeyring });
    const firstRoom = await firstClient.join({
      roomId: "persisted-elo",
      crdtAdaptor: firstAdaptor,
    });
    firstAdaptor.getDoc().getText("text").insert(0, "survives restart");
    firstAdaptor.getDoc().commit();
    await waitUntil(
      () =>
        firstAdaptor.getDoc().getText("text").toString() === "survives restart",
      2_000
    );
    firstKeyring.addKey("key-2", rotatedKey);
    firstKeyring.setActiveKey("key-2");
    await firstAdaptor.publishSnapshot();
    await new Promise(resolve => setTimeout(resolve, 150));
    await firstRoom.destroy();
    firstClient.destroy();

    let stopped = false;
    const stopping = firstServer.stop().then(() => {
      stopped = true;
    });
    await saveStarted;
    expect(stopped).toBe(false);
    releaseSave();
    await stopping;
    servers.splice(servers.indexOf(firstServer), 1);

    expect(loadCalls).toContainEqual({
      roomId: "persisted-elo",
      crdt: CrdtType.Elo,
    });
    expect(saveCalls).toEqual([
      { roomId: "persisted-elo", crdt: CrdtType.Elo },
    ]);

    const persisted = stored.get("persisted-elo");
    expect(persisted).toBeDefined();
    if (!persisted) throw new Error("ELO state was not persisted");
    const records = decodeEloContainer(persisted);
    expect(records.length).toBeGreaterThan(0);
    expect(
      records.map((record: Uint8Array) => parseEloRecordHeader(record).kind)
    ).toContain(EloRecordKind.Snapshot);
    const persistedSnapshot = records.find(
      record => parseEloRecordHeader(record).kind === EloRecordKind.Snapshot
    );
    if (!persistedSnapshot)
      throw new Error("Expected a persisted ELO snapshot");
    expect(parseEloRecordHeader(persistedSnapshot).keyId).toBe("key-2");
    expect(
      containsSubarray(persisted, new TextEncoder().encode("survives restart"))
    ).toBe(false);

    const secondPort = await getPort();
    const secondServer = new SimpleServer({
      port: secondPort,
      onLoadDocument: async (roomId, crdt) => {
        loadCalls.push({ roomId, crdt });
        return stored.get(roomId)?.slice() ?? null;
      },
      onSaveDocument: async () => {},
    });
    servers.push(secondServer);
    await secondServer.start();

    const lateClient = new LoroWebsocketClient({
      url: `ws://localhost:${secondPort}`,
      disablePing: true,
    });
    await lateClient.waitConnected();
    const lateAdaptor = new EloAdaptor({
      keyResolver: new EloKeyring(
        [{ keyId: "key-2", key: rotatedKey }],
        "key-2"
      ),
    });
    const lateRoom = await lateClient.join({
      roomId: "persisted-elo",
      crdtAdaptor: lateAdaptor,
    });
    await waitUntil(
      () =>
        lateAdaptor.getDoc().getText("text").toString() === "survives restart",
      5_000
    );
    expect(loadCalls.filter(call => call.crdt === CrdtType.Elo)).toHaveLength(
      2
    );

    await lateRoom.destroy();
    lateClient.destroy();
  }, 15_000);

  it("waits for accepted callback work before completing stop", async () => {
    const port = await getPort();
    let releaseLoad!: () => void;
    const loadGate = new Promise<void>(resolve => {
      releaseLoad = resolve;
    });
    let notifyLoadStarted!: () => void;
    const loadStarted = new Promise<void>(resolve => {
      notifyLoadStarted = resolve;
    });
    const server = new SimpleServer({
      port,
      onLoadDocument: async () => {
        notifyLoadStarted();
        await loadGate;
        return null;
      },
      onSaveDocument: async () => {},
    });
    servers.push(server);
    await server.start();

    const ws = new WebSocket(`ws://localhost:${port}`);
    await waitForOpen(ws);
    ws.send(
      encode({
        type: MessageType.JoinRequest,
        crdt: CrdtType.Elo,
        roomId: "pending-load",
        auth: new Uint8Array(),
        version: new Uint8Array(),
      })
    );
    await loadStarted;

    let stopped = false;
    const stopping = server.stop().then(() => {
      stopped = true;
    });
    await new Promise(resolve => setTimeout(resolve, 25));
    expect(stopped).toBe(false);
    releaseLoad();
    await stopping;
    servers.splice(servers.indexOf(server), 1);
  });

  it("single-flights concurrent loads for the same ELO room", async () => {
    const port = await getPort();
    let loadCalls = 0;
    let releaseLoad!: () => void;
    const loadGate = new Promise<void>(resolve => {
      releaseLoad = resolve;
    });
    let notifyLoadStarted!: () => void;
    const loadStarted = new Promise<void>(resolve => {
      notifyLoadStarted = resolve;
    });
    const server = new SimpleServer({
      port,
      onLoadDocument: async () => {
        loadCalls++;
        notifyLoadStarted();
        await loadGate;
        return null;
      },
    });
    servers.push(server);
    await server.start();

    const first = new WebSocket(`ws://localhost:${port}`);
    const second = new WebSocket(`ws://localhost:${port}`);
    await Promise.all([waitForOpen(first), waitForOpen(second)]);
    const join = encode({
      type: MessageType.JoinRequest,
      crdt: CrdtType.Elo,
      roomId: "single-flight-load",
      auth: new Uint8Array(),
      version: new Uint8Array(),
    });
    const firstResponse = nextProtocolMessage(first);
    const secondResponse = nextProtocolMessage(second);
    first.send(join);
    second.send(join);

    await loadStarted;
    await new Promise(resolve => setTimeout(resolve, 25));
    expect(loadCalls).toBe(1);
    releaseLoad();
    expect((await firstResponse).type).toBe(MessageType.JoinResponseOk);
    expect((await secondResponse).type).toBe(MessageType.JoinResponseOk);
    first.close();
    second.close();
  });

  it("rejects corrupt loaded ELO state without saving a replacement", async () => {
    const port = await getPort();
    let saves = 0;
    const server = new SimpleServer({
      port,
      onLoadDocument: async () => new Uint8Array([0xff]),
      onSaveDocument: async () => {
        saves++;
      },
    });
    servers.push(server);
    await server.start();

    const ws = new WebSocket(`ws://localhost:${port}`);
    await waitForOpen(ws);
    ws.send(
      encode({
        type: MessageType.JoinRequest,
        crdt: CrdtType.Elo,
        roomId: "corrupt-load",
        auth: new Uint8Array(),
        version: new Uint8Array(),
      })
    );
    const response = await nextProtocolMessage(ws);
    expect(response.type).toBe(MessageType.JoinError);

    ws.send(
      encode({
        type: MessageType.DocUpdate,
        crdt: CrdtType.Elo,
        roomId: "corrupt-load",
        updates: [encodeEloContainer([snapshotRecord(new Uint8Array([1]))])],
        batchId: "0x0102030405060708",
      })
    );
    const ack = await nextProtocolMessage(ws);
    expect(ack.type).toBe(MessageType.Ack);
    if (ack.type !== MessageType.Ack) throw new Error("expected Ack");
    expect(ack.status).toBe(UpdateStatusCode.PermissionDenied);

    await server.stop();
    servers.splice(servers.indexOf(server), 1);
    expect(saves).toBe(0);
  });

  it("fragments restored opaque backfill without changing record bytes", async () => {
    const ciphertext = new Uint8Array(300 * 1024).fill(0xa5);
    const snapshot = snapshotRecord(ciphertext);
    const persisted = encodeEloContainer([snapshot]);
    const port = await getPort();
    const server = new SimpleServer({
      port,
      onLoadDocument: async () => persisted.slice(),
      onSaveDocument: async () => {},
    });
    servers.push(server);
    await server.start();

    const ws = new WebSocket(`ws://localhost:${port}`);
    const messages = createProtocolMessageQueue(ws);
    await waitForOpen(ws);
    ws.send(
      encode({
        type: MessageType.JoinRequest,
        crdt: CrdtType.Elo,
        roomId: "large-restored",
        auth: new Uint8Array(),
        version: new Uint8Array(),
      })
    );

    let fragmentCount = 0;
    let totalSize = 0;
    const fragments = new Map<number, Uint8Array>();
    while (fragments.size === 0 || fragments.size < fragmentCount) {
      const message = await messages.next();
      if (message.type === MessageType.DocUpdateFragmentHeader) {
        fragmentCount = message.fragmentCount;
        totalSize = message.totalSizeBytes;
      } else if (message.type === MessageType.DocUpdateFragment) {
        fragments.set(message.index, message.fragment);
      }
    }
    const restored = new Uint8Array(totalSize);
    let offset = 0;
    for (let index = 0; index < fragmentCount; index++) {
      const fragment = fragments.get(index);
      if (!fragment) throw new Error(`missing fragment ${index}`);
      restored.set(fragment, offset);
      offset += fragment.length;
    }
    expect(restored).toEqual(persisted);
    expect(decodeEloContainer(restored)).toEqual([snapshot]);
  }, 10_000);

  it("serializes saves and preserves updates that race a pending callback", async () => {
    const port = await getPort();
    const saved: Uint8Array[] = [];
    let activeSaves = 0;
    let maxActiveSaves = 0;
    let releaseFirstSave!: () => void;
    const firstSaveGate = new Promise<void>(resolve => {
      releaseFirstSave = resolve;
    });
    let notifyFirstSave!: () => void;
    const firstSaveStarted = new Promise<void>(resolve => {
      notifyFirstSave = resolve;
    });
    const server = new SimpleServer({
      port,
      saveInterval: 10,
      onLoadDocument: async () => null,
      onSaveDocument: async (_roomId, crdt, data) => {
        expect(crdt).toBe(CrdtType.Elo);
        activeSaves++;
        maxActiveSaves = Math.max(maxActiveSaves, activeSaves);
        saved.push(data.slice());
        try {
          if (saved.length === 1) {
            notifyFirstSave();
            await firstSaveGate;
          }
          await new Promise(resolve => setTimeout(resolve, 5));
        } finally {
          activeSaves--;
        }
      },
    });
    servers.push(server);
    await server.start();

    const key = new Uint8Array(16);
    key[0] = 7;
    const client = new LoroWebsocketClient({
      url: `ws://localhost:${port}`,
      disablePing: true,
    });
    await client.waitConnected();
    const adaptor = new EloAdaptor({
      getPrivateKey: async () => ({ keyId: "key-1", key }),
    });
    const room = await client.join({
      roomId: "save-race",
      crdtAdaptor: adaptor,
    });
    const text = adaptor.getDoc().getText("text");
    text.insert(0, "first");
    adaptor.getDoc().commit();

    await firstSaveStarted;
    text.insert(text.length, " second");
    adaptor.getDoc().commit();
    await new Promise(resolve => setTimeout(resolve, 50));
    releaseFirstSave();

    await waitUntil(() => saved.length >= 2, 5_000);
    expect(maxActiveSaves).toBe(1);
    const latestSave = saved.at(-1);
    expect(latestSave).toBeDefined();
    expect(latestSave).not.toEqual(saved[0]);
    if (!latestSave) throw new Error("latest ELO save is missing");
    expect(decodeEloContainer(latestSave)).not.toHaveLength(0);

    await room.destroy();
    client.destroy();
  }, 10_000);
});

async function waitForOpen(ws: WebSocket): Promise<void> {
  if (ws.readyState === WebSocket.OPEN) return;
  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
}

function createProtocolMessageQueue(ws: WebSocket): {
  next: () => Promise<ProtocolMessage>;
} {
  const queued: ProtocolMessage[] = [];
  const waiters: Array<(message: ProtocolMessage) => void> = [];
  ws.on("message", data => {
    const bytes =
      data instanceof Buffer
        ? new Uint8Array(data)
        : new Uint8Array(data as ArrayBuffer);
    const message = tryDecode(bytes);
    if (!message) return;
    const waiter = waiters.shift();
    if (waiter) waiter(message);
    else queued.push(message);
  });
  return {
    next: async () => {
      const message = queued.shift();
      if (message) return message;
      return await new Promise(resolve => waiters.push(resolve));
    },
  };
}

async function nextProtocolMessage(ws: WebSocket): Promise<ProtocolMessage> {
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("message timeout"));
    }, 5_000);
    ws.once("message", data => {
      clearTimeout(timeout);
      const bytes =
        data instanceof Buffer
          ? new Uint8Array(data)
          : new Uint8Array(data as ArrayBuffer);
      const message = tryDecode(bytes);
      if (message) resolve(message);
      else reject(new Error("invalid protocol message"));
    });
  });
}

function snapshotRecord(ciphertext: Uint8Array): Uint8Array {
  const writer = new BytesWriter();
  writer.pushByte(EloRecordKind.Snapshot);
  writer.pushUleb128(1);
  writer.pushVarBytes(new TextEncoder().encode("7"));
  writer.pushUleb128(1);
  writer.pushVarString("key-1");
  writer.pushVarBytes(new Uint8Array(12).fill(7));
  writer.pushVarBytes(ciphertext);
  return writer.finalize();
}

function containsSubarray(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  for (let offset = 0; offset <= haystack.length - needle.length; offset++) {
    if (needle.every((byte, index) => haystack[offset + index] === byte)) {
      return true;
    }
  }
  return false;
}

async function waitUntil(
  condition: () => boolean,
  timeoutMs: number,
  intervalMs = 25
): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (condition()) return;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error("condition was not met before timeout");
}
