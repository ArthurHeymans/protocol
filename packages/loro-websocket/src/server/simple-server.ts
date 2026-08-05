import { WebSocketServer, WebSocket } from "ws";
import { randomBytes } from "node:crypto";
import type { RawData } from "ws";
import type { IncomingMessage } from "node:http";
// no direct CRDT imports here; handled by CrdtDoc implementations
import {
  encode,
  decode,
  CrdtType,
  MessageType,
  type JoinRequest,
  type JoinResponseOk,
  type JoinError,
  JoinErrorCode,
  type DocUpdate,
  type Ack,
  UpdateStatusCode,
  type Leave,
  type ProtocolMessage,
  type Permission,
  type RoomId,
  type HexString,
  type DocUpdateFragmentHeader,
  type DocUpdateFragment,
  MAX_MESSAGE_SIZE,
} from "loro-protocol";
import {
  getServerAdaptorDescriptor,
  type ServerAdaptorDescriptor,
} from "./crdt-doc";

export interface SimpleServerConfig {
  port: number;
  host?: string; // default 127.0.0.1 to avoid sandbox binding errors
  saveInterval?: number;
  /** Maximum fragments declared by one batch. Defaults to 64. */
  maxFragmentsPerBatch?: number;
  /** Maximum reassembled bytes declared by one batch. Defaults to 8 MiB. */
  maxFragmentBatchBytes?: number;
  /** Maximum incomplete batches retained for one connection. Defaults to 8. */
  maxInflightFragmentBatchesPerConnection?: number;
  /** Maximum declared bytes retained for one connection. Defaults to 16 MiB. */
  maxInflightFragmentBytesPerConnection?: number;
  /** Incomplete fragment lifetime in milliseconds. Defaults to 10 seconds. */
  fragmentReassemblyTimeoutMs?: number;
  onLoadDocument?: (
    roomId: string,
    crdtType: CrdtType
  ) => Promise<Uint8Array | null>;
  onSaveDocument?: (
    roomId: string,
    crdtType: CrdtType,
    data: Uint8Array
  ) => Promise<void>;
  /** Map join payload (`auth`) to permission; return null to reject. */
  authenticate?: (
    roomId: string,
    crdtType: CrdtType,
    auth: Uint8Array
  ) => Promise<Permission | null>;
  /**
   * Optional handshake auth: called during WS HTTP upgrade.
   * Return true to accept, false to reject.
   */
  handshakeAuth?: (req: IncomingMessage) => boolean | Promise<boolean>;
}

interface RoomDocument {
  data: Uint8Array;
  descriptor: ServerAdaptorDescriptor;
  lastSaved: number;
  dirty: boolean;
  generation: number;
}

interface ClientConnection {
  ws: WebSocket;
  rooms: Set<string>;
  fragments: Map<
    string,
    {
      data: Array<Uint8Array | undefined>;
      totalSize: number;
      received: number;
      receivedBytes: number;
      header: DocUpdateFragmentHeader;
      timeoutId?: NodeJS.Timeout;
    }
  >;
  permissions: Map<string, Permission>; // roomKey -> permission
  messageChain: Promise<void>;
}

export class SimpleServer {
  private wss?: WebSocketServer;
  private rooms = new Map<string, RoomDocument>();
  private roomLoads = new Map<string, Promise<RoomDocument>>();
  private clients = new WeakMap<WebSocket, ClientConnection>();
  private saveTimer?: NodeJS.Timeout;
  private saveChain: Promise<void> = Promise.resolve();
  private inFlightMessages = new Set<Promise<void>>();
  private stopping = false;
  private config: SimpleServerConfig;
  private static readonly DEFAULT_SAVE_INTERVAL = 60000; // 1 minute
  private static readonly DEFAULT_MAX_FRAGMENTS_PER_BATCH = 64;
  private static readonly DEFAULT_MAX_FRAGMENT_BATCH_BYTES = 8 * 1024 * 1024;
  private static readonly DEFAULT_MAX_INFLIGHT_FRAGMENT_BATCHES = 8;
  private static readonly DEFAULT_MAX_INFLIGHT_FRAGMENT_BYTES =
    16 * 1024 * 1024;
  private static readonly DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT_MS = 10_000;

  constructor(config: SimpleServerConfig) {
    this.config = config;
  }

  start(): Promise<void> {
    this.stopping = false;
    return new Promise(resolve => {
      const options: {
        port: number;
        host?: string;
        maxPayload: number;
        verifyClient?: (
          info: { origin: string; secure: boolean; req: IncomingMessage },
          cb: (res: boolean, code?: number, message?: string) => void
        ) => void;
      } = {
        port: this.config.port,
        maxPayload: MAX_MESSAGE_SIZE,
      };
      if (this.config.host) {
        options.host = this.config.host;
      }
      if (this.config.handshakeAuth) {
        options.verifyClient = (
          info: { origin: string; secure: boolean; req: IncomingMessage },
          cb: (res: boolean, code?: number, message?: string) => void
        ) => {
          Promise.resolve(this.config.handshakeAuth!(info.req))
            .then(allowed => {
              if (allowed) cb(true);
              else cb(false, 401, "Unauthorized");
            })
            .catch(err => {
              console.error("Handshake auth error", err);
              cb(false, 500, "Internal Server Error");
            });
        };
      }
      this.wss = new WebSocketServer(options);

      this.wss.on("connection", ws => {
        const client: ClientConnection = {
          ws,
          rooms: new Set(),
          fragments: new Map(),
          permissions: new Map(),
          messageChain: Promise.resolve(),
        };
        this.clients.set(ws, client);

        ws.on("message", (data: RawData, isBinary: boolean) => {
          if (this.stopping) return;
          try {
            const bytes = this.toUint8Array(data);
            // TODO: REVIEW keepalive handling (app-level ping/pong per protocol.md)
            // Keepalive: reply to text "ping", ignore text "pong"
            if (!isBinary) {
              const str = new TextDecoder().decode(bytes);
              if (str === "ping") {
                if (ws.readyState === WebSocket.OPEN) ws.send("pong");
                return;
              }
              if (str === "pong") return;
              // Ignore other text frames
              return;
            }

            const message = decode(bytes);
            this.enqueueMessage(client, message);
          } catch (error) {
            console.error("Failed to decode message:", error);
            ws.close(1002, "Protocol error");
          }
        });

        ws.on("close", () => {
          this.handleDisconnect(client);
        });
      });

      if (this.config.onSaveDocument) {
        const saveInterval =
          this.config.saveInterval ?? SimpleServer.DEFAULT_SAVE_INTERVAL;
        this.saveTimer = setInterval(() => {
          void this.saveAllDirtyDocuments();
        }, saveInterval);
      }

      this.wss.on("listening", resolve);
    });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.saveTimer) {
      clearInterval(this.saveTimer);
      this.saveTimer = undefined;
    }

    const wss = this.wss;
    if (wss) {
      await Promise.all(
        Array.from(wss.clients).map(ws => this.gracefulCloseWebSocket(ws))
      ).catch(() => {});
    }

    // Closing clients prevents new work; awaiting accepted handlers prevents an
    // already-started update or load from racing the final save.
    await Promise.allSettled(this.inFlightMessages);
    await this.saveAllDirtyDocuments(true);

    if (!wss) return;
    await new Promise<void>(resolve => {
      try {
        wss.close(() => {
          resolve();
        });
      } catch {
        resolve();
      }
    });
    this.wss = undefined;
  }

  private async gracefulCloseWebSocket(ws: WebSocket): Promise<void> {
    try {
      await this.waitForSocketDrain(ws);
    } catch (error) {
      void error;
    }

    try {
      ws.close(1001, "Server stopping");
    } catch (error) {
      void error;
    }

    setTimeout(() => {
      try {
        if (ws.readyState !== WebSocket.CLOSED) ws.terminate();
      } catch (error) {
        void error;
      }
    }, 50);
  }

  private waitForSocketDrain(ws: WebSocket, timeoutMs = 2000): Promise<void> {
    const readBufferedAmount = (): number | undefined => {
      const raw = Reflect.get(ws, "bufferedAmount") as unknown;
      return typeof raw === "number" ? raw : undefined;
    };

    if (readBufferedAmount() == null) return Promise.resolve();

    return new Promise(resolve => {
      const start = Date.now();
      const poll = () => {
        const state = ws.readyState;
        if (state === WebSocket.CLOSING || state === WebSocket.CLOSED) {
          resolve();
          return;
        }

        const buffered = readBufferedAmount();
        if (
          buffered == null ||
          buffered <= 0 ||
          Date.now() - start >= timeoutMs
        ) {
          resolve();
          return;
        }

        setTimeout(poll, 25);
      };

      poll();
    });
  }

  private toUint8Array(data: RawData): Uint8Array {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data))
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(data))
      return new Uint8Array(data);
    if (Array.isArray(data)) {
      // Buffer[]
      const total = data.reduce((s, b) => s + b.length, 0);
      const out = new Uint8Array(total);
      let off = 0;
      for (const b of data) {
        out.set(b, off);
        off += b.length;
      }
      return out;
    }
    throw new Error("Unsupported message data type");
  }

  private enqueueMessage(
    client: ClientConnection,
    message: ProtocolMessage
  ): void {
    const handling = client.messageChain.then(() =>
      this.handleMessage(client, message)
    );
    this.inFlightMessages.add(handling);
    client.messageChain = handling.catch(error => {
      console.error("Failed to handle message:", error);
      client.ws.close(1002, "Protocol error");
    });
    void client.messageChain.finally(() => {
      this.inFlightMessages.delete(handling);
    });
  }

  private async handleMessage(
    client: ClientConnection,
    message: ProtocolMessage
  ): Promise<void> {
    switch (message.type) {
      case MessageType.JoinRequest:
        await this.handleJoinRequest(client, message);
        break;
      case MessageType.DocUpdate:
        await this.handleDocUpdate(client, message);
        break;
      case MessageType.DocUpdateFragmentHeader:
        this.handleFragmentHeader(client, message);
        break;
      case MessageType.DocUpdateFragment:
        await this.handleFragment(client, message);
        break;
      case MessageType.Leave:
        this.handleLeave(client, message);
        break;
      case MessageType.Ack:
        // Clients may report failures when they cannot apply a server update.
        if (message.status !== UpdateStatusCode.Ok) {
          console.warn(
            `Client reported update failure for ${message.crdt}:${message.roomId} ref ${message.refId} status ${message.status}`
          );
        }
        break;
      case MessageType.RoomError:
        // Server does not expect these from clients; ignore.
        break;
      default:
        throw new Error(`Unsupported message type: ${message.type}`);
    }
  }

  private async handleJoinRequest(
    client: ClientConnection,
    message: JoinRequest
  ): Promise<void> {
    try {
      // Authenticate if configured
      let permission: Permission = "write";
      if (this.config.authenticate) {
        const authResult = await this.config.authenticate(
          message.roomId,
          message.crdt,
          message.auth
        );
        if (!authResult) {
          this.sendJoinError(
            client,
            message,
            JoinErrorCode.AuthFailed,
            "Authentication failed"
          );
          return;
        }
        permission = authResult;
      }

      const roomDoc = await this.getOrCreateRoomDocument(
        message.roomId,
        message.crdt
      );
      const roomKey = this.getRoomKey(message.roomId, message.crdt);
      const joinResult = roomDoc.descriptor.adaptor.handleJoinRequest(
        roomDoc.data,
        message.version
      );

      // Register membership only after loading and join preparation succeed.
      client.rooms.add(roomKey);
      client.permissions.set(roomKey, permission);

      // Send join response with current document version
      const response: JoinResponseOk = {
        ...joinResult.response,
        permission,
        crdt: message.crdt,
        roomId: message.roomId,
      };

      this.sendMessage(client.ws, response);
      // Backfill: send the updates the client is missing so it can
      // catch up from its known version to the room’s current state.
      // For Loro this is a delta from the VersionVector; for ELO this
      // is an encrypted container selection; for Ephemeral it's current state.
      const hasOthers = this.hasOtherClientsInRoom(
        message.roomId,
        message.crdt,
        client
      );
      const shouldBackfill =
        (hasOthers || roomDoc.descriptor.allowBackfillWhenNoOtherClients) &&
        joinResult.updates &&
        joinResult.updates.length;

      if (shouldBackfill && joinResult.updates) {
        for (const update of joinResult.updates) {
          this.sendUpdateOrFragments(
            client.ws,
            message.crdt,
            message.roomId,
            update
          );
        }
      }
    } catch (error) {
      this.sendJoinError(
        client,
        message,
        JoinErrorCode.Unknown,
        error instanceof Error ? error.message : "Unknown error"
      );
    }
  }

  private async handleDocUpdate(
    client: ClientConnection,
    message: DocUpdate
  ): Promise<void> {
    try {
      // Guard: reject payloads that exceed max update size
      // (Clients fragment large updates; this is a safety net.)
      const oversized = message.updates.some(
        (update: Uint8Array) => update.length > MAX_MESSAGE_SIZE
      );
      if (oversized) {
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.PayloadTooLarge,
          message.crdt,
          message.roomId
        );
        return;
      }

      const roomKey = this.getRoomKey(message.roomId, message.crdt);

      // Check if client has joined this room
      if (!client.rooms.has(roomKey)) {
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.PermissionDenied,
          message.crdt,
          message.roomId
        );
        return;
      }

      const permission = client.permissions.get(roomKey);

      // Check if client has write permission
      if (permission !== "write") {
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.PermissionDenied,
          message.crdt,
          message.roomId
        );
        return;
      }

      const roomDoc = await this.getOrCreateRoomDocument(
        message.roomId,
        message.crdt
      );

      try {
        const newDocumentData = roomDoc.descriptor.adaptor.applyUpdates(
          roomDoc.data,
          message.updates
        );
        roomDoc.data = newDocumentData;
      } catch (error) {
        console.warn("applyUpdates failed for DocUpdate", error);
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.InvalidUpdate,
          message.crdt,
          message.roomId
        );
        return;
      }

      if (roomDoc.descriptor.shouldPersist) {
        roomDoc.dirty = true;
        roomDoc.generation++;
      }

      const updatesForBroadcast = message.updates;
      // Notify sender
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.Ok,
        message.crdt,
        message.roomId
      );

      if (updatesForBroadcast.length > 0) {
        const outgoing: DocUpdate = {
          type: MessageType.DocUpdate,
          crdt: message.crdt,
          roomId: message.roomId,
          updates: updatesForBroadcast,
          batchId: message.batchId,
        };
        this.broadcastToRoom(message.roomId, message.crdt, outgoing, client);
      }
    } catch (error) {
      console.error(error);
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.Unknown,
        message.crdt,
        message.roomId
      );
    }
  }

  private handleFragmentHeader(
    client: ClientConnection,
    message: DocUpdateFragmentHeader
  ): void {
    const roomKey = this.getRoomKey(message.roomId, message.crdt);
    const fragmentKey = this.getFragmentKey(message);
    if (!client.rooms.has(roomKey)) {
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.PermissionDenied,
        message.crdt,
        message.roomId
      );
      return;
    }

    const maxFragments =
      this.config.maxFragmentsPerBatch ??
      SimpleServer.DEFAULT_MAX_FRAGMENTS_PER_BATCH;
    const maxBatchBytes =
      this.config.maxFragmentBatchBytes ??
      SimpleServer.DEFAULT_MAX_FRAGMENT_BATCH_BYTES;
    const maxBatches =
      this.config.maxInflightFragmentBatchesPerConnection ??
      SimpleServer.DEFAULT_MAX_INFLIGHT_FRAGMENT_BATCHES;
    const maxInflightBytes =
      this.config.maxInflightFragmentBytesPerConnection ??
      SimpleServer.DEFAULT_MAX_INFLIGHT_FRAGMENT_BYTES;
    const validDeclaration =
      Number.isSafeInteger(message.fragmentCount) &&
      message.fragmentCount > 0 &&
      message.fragmentCount <= maxFragments &&
      Number.isSafeInteger(message.totalSizeBytes) &&
      message.totalSizeBytes > 0 &&
      message.totalSizeBytes <= maxBatchBytes;
    if (!validDeclaration) {
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.PayloadTooLarge,
        message.crdt,
        message.roomId
      );
      return;
    }

    const existing = client.fragments.get(fragmentKey);
    const existingBytes = existing?.totalSize ?? 0;
    const inflightBytes = Array.from(client.fragments.values()).reduce(
      (total, batch) => total + batch.totalSize,
      0
    );
    const nextBatchCount = client.fragments.size + (existing ? 0 : 1);
    if (
      nextBatchCount > maxBatches ||
      inflightBytes - existingBytes + message.totalSizeBytes > maxInflightBytes
    ) {
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.RateLimited,
        message.crdt,
        message.roomId
      );
      return;
    }
    if (existing?.timeoutId) clearTimeout(existing.timeoutId);

    const batch = {
      data: Array.from(
        { length: message.fragmentCount },
        (): Uint8Array | undefined => undefined
      ),
      totalSize: message.totalSizeBytes,
      received: 0,
      receivedBytes: 0,
      header: message,
      timeoutId: undefined as NodeJS.Timeout | undefined,
    };
    batch.timeoutId = setTimeout(() => {
      client.fragments.delete(fragmentKey);
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.FragmentTimeout,
        message.crdt,
        message.roomId
      );
    }, this.config.fragmentReassemblyTimeoutMs ?? SimpleServer.DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT_MS);
    client.fragments.set(fragmentKey, batch);
  }

  private async handleFragment(
    client: ClientConnection,
    message: DocUpdateFragment
  ): Promise<void> {
    const fragmentKey = this.getFragmentKey(message);
    const batch = client.fragments.get(fragmentKey);
    if (!batch) {
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.FragmentTimeout,
        message.crdt,
        message.roomId
      );
      return;
    }

    if (
      message.roomId !== batch.header.roomId ||
      message.crdt !== batch.header.crdt ||
      !Number.isSafeInteger(message.index) ||
      message.index < 0 ||
      message.index >= batch.data.length ||
      message.fragment.length > MAX_MESSAGE_SIZE ||
      batch.data[message.index] !== undefined ||
      batch.receivedBytes + message.fragment.length > batch.totalSize
    ) {
      if (batch.timeoutId) clearTimeout(batch.timeoutId);
      client.fragments.delete(fragmentKey);
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.InvalidUpdate,
        message.crdt,
        message.roomId
      );
      return;
    }

    batch.data[message.index] = message.fragment;
    batch.received++;
    batch.receivedBytes += message.fragment.length;

    if (batch.received === batch.data.length) {
      if (batch.timeoutId) clearTimeout(batch.timeoutId);
      if (batch.receivedBytes !== batch.totalSize) {
        client.fragments.delete(fragmentKey);
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.InvalidUpdate,
          message.crdt,
          message.roomId
        );
        return;
      }
      const totalData = new Uint8Array(batch.totalSize);
      let offset = 0;

      for (const fragment of batch.data) {
        if (!fragment) {
          client.fragments.delete(fragmentKey);
          return;
        }
        totalData.set(fragment, offset);
        offset += fragment.length;
      }

      // Apply updates with permission checks, then broadcast the original
      // fragment header and fragments to other clients to avoid oversize
      // DocUpdate messages.
      const roomKey = this.getRoomKey(message.roomId, message.crdt);
      if (!client.rooms.has(roomKey)) {
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.PermissionDenied,
          message.crdt,
          message.roomId
        );
        client.fragments.delete(fragmentKey);
        return;
      }

      const permission = client.permissions.get(roomKey);
      if (permission !== "write") {
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.PermissionDenied,
          message.crdt,
          message.roomId
        );
        client.fragments.delete(fragmentKey);
        return;
      }

      // Apply to server-side CRDT state
      const roomDoc = await this.getOrCreateRoomDocument(
        message.roomId,
        message.crdt
      );
      try {
        const newDocumentData = roomDoc.descriptor.adaptor.applyUpdates(
          roomDoc.data,
          [totalData]
        );
        roomDoc.data = newDocumentData;
      } catch (error) {
        console.warn("applyUpdates failed for fragmented DocUpdate", error);
        this.sendAck(
          client.ws,
          message.batchId,
          UpdateStatusCode.InvalidUpdate,
          message.crdt,
          message.roomId
        );
        client.fragments.delete(fragmentKey);
        return;
      }
      if (roomDoc.descriptor.shouldPersist) {
        roomDoc.dirty = true;
        roomDoc.generation++;
      }

      // Notify sender
      this.sendAck(
        client.ws,
        message.batchId,
        UpdateStatusCode.Ok,
        message.crdt,
        message.roomId
      );

      // Broadcast original fragments to other clients in the room
      const header = client.fragments.get(fragmentKey)!.header;
      this.wss?.clients.forEach(ws => {
        const c = this.clients.get(ws);
        if (!c || c === client) return;
        if (!c.rooms.has(roomKey)) return;
        this.sendMessage(ws, header);
        for (let i = 0; i < batch.data.length; i++) {
          const fragMsg: DocUpdateFragment = {
            type: MessageType.DocUpdateFragment,
            crdt: message.crdt,
            roomId: message.roomId,
            batchId: message.batchId,
            index: i,
            fragment: batch.data[i]!,
          };
          this.sendMessage(ws, fragMsg);
        }
      });

      client.fragments.delete(fragmentKey);
    }
  }

  private getFragmentKey(message: {
    crdt: CrdtType;
    roomId: RoomId;
    batchId: HexString;
  }): string {
    return `${message.crdt}:${message.roomId}:${message.batchId}`;
  }

  private handleLeave(client: ClientConnection, message: Leave): void {
    const roomKey = this.getRoomKey(message.roomId, message.crdt);
    client.rooms.delete(roomKey);
    client.permissions.delete(roomKey);
  }

  private handleDisconnect(client: ClientConnection): void {
    client.rooms.clear();
    for (const [, frag] of client.fragments) {
      if (frag.timeoutId) clearTimeout(frag.timeoutId);
    }
    client.fragments.clear();
    client.permissions.clear();
  }

  private async getOrCreateRoomDocument(
    roomId: RoomId,
    crdtType: CrdtType
  ): Promise<RoomDocument> {
    const roomKey = this.getRoomKey(roomId, crdtType);

    const roomDoc = this.rooms.get(roomKey);
    if (roomDoc) return roomDoc;

    const existingLoad = this.roomLoads.get(roomKey);
    if (existingLoad) return existingLoad;

    const loading = (async (): Promise<RoomDocument> => {
      const descriptor = getServerAdaptorDescriptor(crdtType);
      if (!descriptor) throw new Error("Unsupported CRDT type");

      let data = descriptor.adaptor.createEmpty();
      if (descriptor.shouldPersist && this.config.onLoadDocument) {
        try {
          const loaded = await this.config.onLoadDocument(roomId, crdtType);
          if (loaded) data = loaded;
        } catch (error) {
          console.warn("Failed to load document:", error);
          throw error;
        }
      }

      const loadedRoom: RoomDocument = {
        data,
        descriptor,
        lastSaved: Date.now(),
        dirty: false,
        generation: 0,
      };
      this.rooms.set(roomKey, loadedRoom);
      return loadedRoom;
    })();
    this.roomLoads.set(roomKey, loading);
    try {
      return await loading;
    } finally {
      if (this.roomLoads.get(roomKey) === loading) {
        this.roomLoads.delete(roomKey);
      }
    }
  }

  private sendJoinError(
    client: ClientConnection,
    message: JoinRequest,
    code: JoinErrorCode,
    errorMessage: string
  ): void {
    const error: JoinError = {
      type: MessageType.JoinError,
      crdt: message.crdt,
      roomId: message.roomId,
      code,
      message: errorMessage,
    };
    this.sendMessage(client.ws, error);
  }

  private sendMessage(ws: WebSocket, message: ProtocolMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      const data = encode(message);
      ws.send(data);
    }
  }

  private sendUpdateOrFragments(
    ws: WebSocket,
    crdt: CrdtType,
    roomId: RoomId,
    update: Uint8Array
  ): void {
    const fragmentSize = Math.max(
      1,
      Math.min(240 * 1024, MAX_MESSAGE_SIZE - 4096)
    );
    const batchId = this.newBatchId();
    if (update.length <= fragmentSize) {
      this.sendMessage(ws, {
        type: MessageType.DocUpdate,
        crdt,
        roomId,
        updates: [update],
        batchId,
      });
      return;
    }

    const fragmentCount = Math.ceil(update.length / fragmentSize);
    this.sendMessage(ws, {
      type: MessageType.DocUpdateFragmentHeader,
      crdt,
      roomId,
      batchId,
      fragmentCount,
      totalSizeBytes: update.length,
    });
    for (let index = 0; index < fragmentCount; index++) {
      const start = index * fragmentSize;
      this.sendMessage(ws, {
        type: MessageType.DocUpdateFragment,
        crdt,
        roomId,
        batchId,
        index,
        fragment: update.subarray(
          start,
          Math.min(start + fragmentSize, update.length)
        ),
      });
    }
  }

  private newBatchId(): HexString {
    return `0x${randomBytes(8).toString("hex")}`;
  }

  private sendAck(
    ws: WebSocket,
    refId: HexString,
    status: UpdateStatusCode,
    crdt: CrdtType,
    roomId: RoomId
  ): void {
    const ack: Ack = {
      type: MessageType.Ack,
      crdt,
      roomId,
      refId,
      status,
    };
    this.sendMessage(ws, ack);
  }

  private broadcastToRoom(
    roomId: RoomId,
    crdtType: CrdtType,
    message: ProtocolMessage,
    excludeClient?: ClientConnection
  ): void {
    const roomKey = this.getRoomKey(roomId, crdtType);

    this.wss?.clients.forEach(ws => {
      const client = this.clients.get(ws);
      if (client && client !== excludeClient && client.rooms.has(roomKey)) {
        // console.log("send message to client", JSON.stringify(message))
        this.sendMessage(ws, message);
      }
    });
  }

  private hasOtherClientsInRoom(
    roomId: RoomId,
    crdtType: CrdtType,
    excludeClient?: ClientConnection
  ): boolean {
    const roomKey = this.getRoomKey(roomId, crdtType);
    let count = 0;
    this.wss?.clients.forEach(ws => {
      const c = this.clients.get(ws);
      if (!c) return;
      if (excludeClient && c === excludeClient) return;
      if (c.rooms.has(roomKey)) count++;
    });
    return count > 0;
  }

  private getRoomKey(roomId: RoomId, crdtType: CrdtType): string {
    return `${roomId}:${crdtType}`;
  }

  private parseRoomKey(roomKey: string): {
    roomId: string;
    crdtType: CrdtType;
  } {
    const sep = roomKey.lastIndexOf(":");
    if (sep === -1) {
      return { roomId: roomKey, crdtType: CrdtType.Loro };
    }
    const roomId = roomKey.slice(0, sep);
    const crdtType = roomKey.slice(sep + 1) as CrdtType;
    return { roomId, crdtType };
  }

  private saveAllDirtyDocuments(propagateErrors = false): Promise<void> {
    const queuedSave = this.saveChain.then(() =>
      this.saveAllDirtyDocumentsOnce(propagateErrors)
    );
    this.saveChain = queuedSave.catch(() => {});
    return queuedSave;
  }

  private async saveAllDirtyDocumentsOnce(
    propagateErrors: boolean
  ): Promise<void> {
    if (!this.config.onSaveDocument) return;

    const errors: unknown[] = [];
    for (const [roomKey, roomDoc] of this.rooms) {
      if (!roomDoc.dirty || !roomDoc.descriptor.shouldPersist) continue;
      const generation = roomDoc.generation;
      const data = roomDoc.data;
      try {
        const { roomId, crdtType } = this.parseRoomKey(roomKey);
        await this.config.onSaveDocument(roomId, crdtType, data);
        if (roomDoc.generation === generation) {
          roomDoc.dirty = false;
        }
        roomDoc.lastSaved = Date.now();
      } catch (error) {
        console.error("Failed to save document:", error);
        errors.push(error);
      }
    }
    if (propagateErrors && errors.length > 0) {
      throw errors[0];
    }
  }
}
