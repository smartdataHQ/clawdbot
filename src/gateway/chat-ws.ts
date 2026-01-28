/**
 * Chat WebSocket Handler
 *
 * Implements the `/ws/:chatId` WebSocket endpoint expected by the
 * cxs-agents basic frontend. Provides bidirectional streaming for
 * chat messages, tool output, heartbeats, and JSON-RPC.
 *
 * Protocol:
 *   Client → Server:
 *     { session_id, user_id, message }          — send chat message
 *     { type: "heartbeat" }                     — keepalive
 *     { type: "chat-stop", chatId }             — stop streaming
 *     { type: "tool-output", toolCallId, output, isError }
 *     { type: "tools-changed", tools }          — browser tools update
 *     { type: "rpc-response", jsonrpc, id, result/error }
 *     { type: "rpc-request", jsonrpc, id, method, params }
 *
 *   Server → Client:
 *     StreamEvent objects (text-delta, tool-invocation, finish, etc.)
 *     { type: "rpc-request", ... }
 *     { type: "rpc-notification", ... }
 *     { type: "rpc-response", ... }
 */

import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

import { WebSocketServer, type WebSocket } from "ws";

import { loadConfig } from "../config/config.js";
import { createDefaultDeps } from "../cli/deps.js";
import { agentCommand } from "../commands/agent.js";
import { emitAgentEvent, onAgentEvent } from "../infra/agent-events.js";
import { defaultRuntime } from "../runtime.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";
import { resolveAgentIdForRequest, resolveSessionKey } from "./http-utils.js";

export interface ChatWsOptions {
  auth: ResolvedGatewayAuth;
  trustedProxies?: string[];
}

interface BrowserToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  requiresPermission?: string[];
  fireAndForget?: boolean;
}

interface ChatWsClient {
  ws: WebSocket;
  chatId: string;
  userId: string;
  sessionKey: string;
  runId: string | null;
  browserTools: BrowserToolDefinition[];
  pendingRpcCallbacks: Map<
    string,
    {
      resolve: (result: unknown) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >;
}

/**
 * Create a WebSocket server for `/ws/:chatId` chat connections.
 */
export function createChatWsServer(opts: ChatWsOptions): {
  handleUpgrade: (req: IncomingMessage, socket: Duplex, head: Buffer) => boolean;
} {
  const wss = new WebSocketServer({ noServer: true });

  function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): boolean {
    const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);

    // Match /ws/:chatId
    const match = url.pathname.match(/^\/ws\/(.+)$/);
    if (!match) return false;

    const chatId = decodeURIComponent(match[1]!);
    const userId = url.searchParams.get("user_id") || "1";

    // Auth: check Bearer token from header, query, or allow localhost
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : url.searchParams.get("token") || undefined;

    wss.handleUpgrade(req, socket, head, async (ws) => {
      // Authenticate — allow localhost connections without token (dev convenience)
      const remoteAddr = (socket as unknown as { remoteAddress?: string }).remoteAddress;
      const isLocalhost =
        remoteAddr === "127.0.0.1" || remoteAddr === "::1" || remoteAddr === "::ffff:127.0.0.1";

      if (!isLocalhost || token) {
        const authResult = await authorizeGatewayConnect({
          auth: opts.auth,
          connectAuth: { token, password: token },
          req,
          trustedProxies: opts.trustedProxies,
        });

        if (!authResult.ok) {
          ws.close(4001, "Unauthorized");
          return;
        }
      }

      const agentId = "main";
      // Use chatId as session key directly (frontend sends the session key as chatId)
      const sessionKey = chatId;

      const client: ChatWsClient = {
        ws,
        chatId,
        userId,
        sessionKey,
        runId: null,
        browserTools: [],
        pendingRpcCallbacks: new Map(),
      };

      handleConnection(client);
    });

    return true;
  }

  function handleConnection(client: ChatWsClient) {
    const { ws } = client;

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());
        handleClientMessage(client, msg);
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on("close", () => {
      // Clean up pending RPC callbacks
      for (const [, cb] of client.pendingRpcCallbacks) {
        clearTimeout(cb.timer);
        cb.reject(new Error("WebSocket closed"));
      }
      client.pendingRpcCallbacks.clear();
      client.browserTools = [];
    });

    ws.on("error", () => {
      // Ignore
    });
  }

  function handleClientMessage(client: ChatWsClient, msg: Record<string, unknown>) {
    const type = msg.type as string | undefined;

    // Heartbeat
    if (type === "heartbeat") {
      return; // No response needed
    }

    // Chat stop
    if (type === "chat-stop") {
      // TODO: implement abort for active run
      return;
    }

    // Tool output
    if (type === "tool-output") {
      // TODO: forward tool output to agent
      return;
    }

    // Tools changed notification
    if (type === "tools-changed") {
      const tools = msg.tools as BrowserToolDefinition[] | undefined;
      client.browserTools = Array.isArray(tools) ? tools : [];
      return;
    }

    // RPC response from client
    if (type === "rpc-response") {
      const id = msg.id as string;
      const pending = client.pendingRpcCallbacks.get(id);
      if (pending) {
        client.pendingRpcCallbacks.delete(id);
        clearTimeout(pending.timer);
        if (msg.error) {
          const err = msg.error as { message?: string };
          pending.reject(new Error(err.message || "RPC error"));
        } else {
          pending.resolve(msg.result);
        }
      }
      return;
    }

    // RPC request from client (e.g. canvas_action)
    if (type === "rpc-request") {
      const method = msg.method as string;
      const id = msg.id as string;
      const params = (msg.params as Record<string, unknown>) || {};

      const sendResponse = (result: unknown, error?: { code: number; message: string }) => {
        if (client.ws.readyState === client.ws.OPEN) {
          const resp: Record<string, unknown> = {
            type: "rpc-response",
            jsonrpc: "2.0",
            id,
          };
          if (error) {
            resp.error = error;
          } else {
            resp.result = result;
          }
          client.ws.send(JSON.stringify(resp));
        }
      };

      if (method === "canvas_action") {
        // Forward canvas action to agent as a message
        const canvasId = (params.canvasId as string) || "default";
        const action = params.action as Record<string, unknown> | undefined;
        if (action) {
          const actionMsg = `[Canvas action on ${canvasId}: ${JSON.stringify(action)}]`;
          handleChatMessage(client, actionMsg);
          sendResponse({ ok: true });
        } else {
          sendResponse(null, { code: -32602, message: "Missing action params" });
        }
      } else {
        sendResponse(null, { code: -32601, message: `Method not found: ${method}` });
      }
      return;
    }

    // Chat message (no type field, has message + session_id + user_id)
    if (msg.message && typeof msg.message === "string") {
      handleChatMessage(client, msg.message as string);
      return;
    }
  }

  function handleChatMessage(client: ChatWsClient, message: string) {
    const { ws, sessionKey } = client;
    const runId = `resp_${randomUUID()}`;
    client.runId = runId;

    let accumulatedText = "";
    let sawDelta = false;
    let closed = false;

    const send = (event: Record<string, unknown>) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify(event));
      }
    };

    const unsubscribe = onAgentEvent((evt) => {
      if (evt.runId !== runId) return;
      if (closed) return;

      if (evt.stream === "assistant") {
        const delta = evt.data?.delta;
        const text = evt.data?.text;
        const content = typeof delta === "string" ? delta : typeof text === "string" ? text : "";
        if (!content) return;

        sawDelta = true;
        accumulatedText += content;

        send({ type: "text-delta", delta: content });
        return;
      }

      if (evt.stream === "tool") {
        const phase = evt.data?.phase;
        const toolName = evt.data?.name as string | undefined;
        const toolCallId = (evt.data?.toolCallId as string) ?? "";

        if (phase === "start" && toolName) {
          const args = (evt.data?.args as Record<string, unknown>) ?? {};

          // AI SDK format
          send({ type: "tool-input-start", toolCallId, toolName });
          send({ type: "tool-input-available", toolCallId, toolName, input: args });

          // tool-invocation format
          send({ type: "tool-invocation", toolCallId, toolName, args, state: "running" });
        }

        if (phase === "result" && toolName) {
          const isError = Boolean(evt.data?.isError);
          const result = evt.data?.result;
          const args = (evt.data?.args as Record<string, unknown>) ?? {};

          send({ type: "tool-output-available", toolCallId, toolName, output: result ?? null });
          send({
            type: "tool-invocation",
            toolCallId,
            toolName,
            args,
            state: isError ? "failed" : "completed",
            result: result ?? null,
          });

          // File events
          if (!isError) {
            const fileToolNames = ["Write", "write", "Edit", "edit", "create_file", "save_file"];
            const deleteToolNames = ["delete_file", "rm", "remove_file"];
            if (fileToolNames.includes(toolName)) {
              const filePath = (args.path as string) || (args.file_path as string) || "";
              if (filePath) {
                send({
                  type: "data-fileAdded",
                  data: { filename: filePath.split("/").pop(), path: filePath },
                });
              }
            } else if (deleteToolNames.includes(toolName)) {
              const filePath = (args.path as string) || (args.file_path as string) || "";
              if (filePath) {
                send({ type: "data-fileDeleted", data: { path: filePath } });
              }
            }
          }
        }

        // Canvas events
        if (toolName === "canvas") {
          const canvasArgs = evt.data?.args as Record<string, unknown> | undefined;
          const action = canvasArgs?.action as string | undefined;

          if (phase === "start" && (action === "a2ui_push" || action === "a2ui_reset")) {
            const canvasId = "default";
            const artifactId = toolCallId || `canvas_${randomUUID()}`;
            const jsonl = (canvasArgs?.jsonl as string) ?? "";

            if (action === "a2ui_push" && jsonl) {
              const lines = jsonl.split("\n").filter((l: string) => l.trim());
              for (const line of lines) {
                try {
                  const parsed = JSON.parse(line);
                  send({
                    type: "data-canvas-update",
                    data: {
                      canvasId,
                      componentId: parsed.id ?? parsed.componentId,
                      artifactId,
                      jsonTree: parsed,
                      action: "upsert",
                    },
                  });
                } catch {
                  /* skip */
                }
              }
            } else if (action === "a2ui_reset") {
              send({
                type: "data-canvas-update",
                data: { canvasId, artifactId, jsonTree: null, action: "reset" },
              });
            }
          }

          if (phase === "result") {
            const isError = evt.data?.isError;
            const canvasId = "default";
            const artifactId = toolCallId || `canvas_${randomUUID()}`;
            if (isError) {
              send({
                type: "data-canvas-error",
                data: {
                  canvasId,
                  artifactId,
                  error:
                    typeof evt.data?.result === "string"
                      ? evt.data.result
                      : JSON.stringify(evt.data?.result ?? "Canvas error"),
                },
              });
            } else {
              send({
                type: "data-canvas-complete",
                data: { canvasId, artifactId, jsonTree: null },
              });
            }
          }
        }
        return;
      }

      if (evt.stream === "lifecycle") {
        const phase = evt.data?.phase;
        if (phase === "end" || phase === "error") {
          closed = true;
          unsubscribe();

          if (!sawDelta) {
            send({ type: "text-delta", delta: "No response from Clawdbot." });
          }

          send({ type: "finish" });
          client.runId = null;
        }
      }
    });

    ws.on("close", () => {
      closed = true;
      unsubscribe();
    });

    const deps = createDefaultDeps();
    void (async () => {
      try {
        const result = await agentCommand(
          {
            message,
            sessionKey,
            runId,
            deliver: false,
            messageChannel: "webchat",
            bestEffortDeliver: false,
          },
          defaultRuntime,
          deps,
        );

        // If no streaming deltas, send full response
        if (!sawDelta && !closed) {
          const resultAny = result as { payloads?: Array<{ text?: string }> } | null;
          const content =
            Array.isArray(resultAny?.payloads) && resultAny.payloads.length > 0
              ? resultAny.payloads
                  .map((p) => p.text ?? "")
                  .filter(Boolean)
                  .join("\n\n")
              : "No response from Clawdbot.";
          send({ type: "text-delta", delta: content });
        }
      } catch (err) {
        if (!closed) {
          send({ type: "error", errorText: String(err) });
        }
      } finally {
        if (!closed) {
          emitAgentEvent({ runId, stream: "lifecycle", data: { phase: "end" } });
        }
      }
    })();
  }

  return { handleUpgrade };
}
