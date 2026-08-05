import { describe, expect, it, vi } from "vitest";
import {
  CrdtType,
  decode,
  MessageType,
  UpdateStatusCode,
  type DocUpdateFragment,
  type DocUpdateFragmentHeader,
  type ProtocolMessage,
} from "loro-protocol";
import { SimpleServer } from "./simple-server";

describe("SimpleServer ordering and persistence", () => {
  it("processes messages from one connection sequentially", async () => {
    const server = new SimpleServer({ port: 0 });
    const client = fakeClient(server, "room");
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>(resolve => {
      releaseFirst = resolve;
    });
    const events: string[] = [];
    (server as any).handleMessage = vi.fn(
      async (_client: unknown, message: ProtocolMessage) => {
        events.push(message.roomId);
        if (message.roomId === "first") await firstGate;
      }
    );
    const leave = (roomId: string): ProtocolMessage => ({
      type: MessageType.Leave,
      crdt: CrdtType.Loro,
      roomId,
    });

    (server as any).enqueueMessage(client, leave("first"));
    (server as any).enqueueMessage(client, leave("second"));
    await Promise.resolve();
    expect(events).toEqual(["first"]);
    releaseFirst();
    await client.messageChain;
    expect(events).toEqual(["first", "second"]);
  });

  it("propagates a failed final save from stop", async () => {
    const server = new SimpleServer({
      port: 0,
      onSaveDocument: async () => {
        throw new Error("save failed");
      },
    });
    const roomKey = (server as any).getRoomKey("room", CrdtType.Elo);
    (server as any).rooms.set(roomKey, {
      data: new Uint8Array([1]),
      descriptor: { shouldPersist: true },
      lastSaved: 0,
      dirty: true,
      generation: 1,
    });

    await expect(server.stop()).rejects.toThrow("save failed");
  });
});

describe("SimpleServer fragment limits", () => {
  it("rejects over-limit headers before allocating fragment storage", () => {
    const server = new SimpleServer({
      port: 0,
      maxFragmentsPerBatch: 2,
      maxFragmentBatchBytes: 4,
    });
    const client = fakeClient(server, "room");
    const header = fragmentHeader(3, 3);

    (server as any).handleFragmentHeader(client, header);

    expect(client.fragments.size).toBe(0);
    expect(lastAckStatus(client.ws.send)).toBe(
      UpdateStatusCode.PayloadTooLarge
    );
  });

  it("rejects duplicate fragment indices and clears the batch", async () => {
    const server = new SimpleServer({ port: 0 });
    const client = fakeClient(server, "room");
    const header = fragmentHeader(2, 2);
    (server as any).handleFragmentHeader(client, header);

    const fragment: DocUpdateFragment = {
      type: MessageType.DocUpdateFragment,
      crdt: CrdtType.Loro,
      roomId: "room",
      batchId: header.batchId,
      index: 0,
      fragment: new Uint8Array([1]),
    };
    await (server as any).handleFragment(client, fragment);
    await (server as any).handleFragment(client, fragment);

    expect(client.fragments.size).toBe(0);
    expect(lastAckStatus(client.ws.send)).toBe(UpdateStatusCode.InvalidUpdate);
  });
});

function fragmentHeader(
  fragmentCount: number,
  totalSizeBytes: number
): DocUpdateFragmentHeader {
  return {
    type: MessageType.DocUpdateFragmentHeader,
    crdt: CrdtType.Loro,
    roomId: "room",
    batchId: "0x0101010101010101",
    fragmentCount,
    totalSizeBytes,
  };
}

function fakeClient(server: SimpleServer, roomId: string) {
  const ws = { readyState: 1, send: vi.fn() };
  return {
    ws,
    rooms: new Set([(server as any).getRoomKey(roomId, CrdtType.Loro)]),
    fragments: new Map(),
    permissions: new Map([
      [(server as any).getRoomKey(roomId, CrdtType.Loro), "write"],
    ]),
    messageChain: Promise.resolve(),
  };
}

function lastAckStatus(send: ReturnType<typeof vi.fn>): UpdateStatusCode {
  const call = send.mock.calls.at(-1);
  if (!call) throw new Error("expected an ACK");
  const message = decode(call[0] as Uint8Array);
  if (message.type !== MessageType.Ack) throw new Error("expected an ACK");
  return message.status;
}
