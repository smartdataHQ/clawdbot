/**
 * OpenResponses REST API Handler
 *
 * Implements the `/api/*` endpoints expected by the standard cxs-agents
 * basic frontend (Vercel AI SDK). Maps Clawdbot's session store to the
 * Conversation/Message/Agent types the frontend expects.
 *
 * Endpoints:
 *   GET  /api/agents                        → Agent[]
 *   GET  /api/agents/:slug                  → Agent
 *   GET  /api/users/:id/conversations       → Conversation[]
 *   POST /api/users/:id/conversations       → Conversation
 *   GET  /api/conversations/:id             → ConversationDetail (with messages)
 *   PUT  /api/conversations/:id             → Conversation (rename)
 *   DELETE /api/conversations/:id           → void
 *   GET  /api/users/:id                     → User (stub)
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as nodePath from "node:path";
import * as os from "node:os";

import { loadConfig } from "../config/config.js";
import {
  listSessionsFromStore,
  loadCombinedSessionStoreForGateway,
  readSessionPreviewItemsFromTranscript,
  resolveGatewaySessionStoreTarget,
} from "./session-utils.js";
import { loadSessionStore, updateSessionStore } from "../config/sessions.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";
import { getBearerToken } from "./http-utils.js";
import {
  readJsonBodyOrError,
  sendJson,
  sendMethodNotAllowed,
  sendUnauthorized,
} from "./http-common.js";

// ---------------------------------------------------------------------------
// Types matching frontend expectations
// ---------------------------------------------------------------------------

interface ApiAgent {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  endpoint_url: string | null;
  created_at: string;
}

interface ApiMessage {
  id: number;
  text: string;
  sender: "user" | "ai";
  created_at: string;
}

interface ApiConversation {
  id: string;
  session_id: string;
  title: string;
  user_id: number;
  agent_id: number;
  agent: ApiAgent | null;
  created_at: string;
  updated_at: string;
}

interface ApiConversationDetail extends ApiConversation {
  messages: ApiMessage[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function defaultAgent(): ApiAgent {
  return {
    id: 1,
    name: "Clawdbot",
    slug: "main",
    description: "Clawdbot agent",
    endpoint_url: null,
    created_at: new Date().toISOString(),
  };
}

function sessionKeyToConversation(
  key: string,
  session: { updatedAt?: number; displayName?: string; label?: string; derivedTitle?: string },
  title?: string,
): ApiConversation {
  const updatedAt = session.updatedAt
    ? new Date(session.updatedAt).toISOString()
    : new Date().toISOString();
  return {
    id: key,
    session_id: key,
    title: title ?? session.derivedTitle ?? session.displayName ?? session.label ?? key,
    user_id: 1,
    agent_id: 1,
    agent: defaultAgent(),
    created_at: updatedAt,
    updated_at: updatedAt,
  };
}

function previewItemsToMessages(
  items: Array<{ role: string; text: string }>,
  baseTime: string,
): ApiMessage[] {
  return items.map((item, i) => ({
    id: i + 1,
    text: item.text,
    sender: item.role === "user" ? ("user" as const) : ("ai" as const),
    created_at: baseTime,
  }));
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface OpenResponsesApiOptions {
  auth: ResolvedGatewayAuth;
  trustedProxies?: string[];
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export async function handleOpenResponsesApiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: OpenResponsesApiOptions,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);

  if (!url.pathname.startsWith("/api/")) return false;

  // Auth
  const token = getBearerToken(req);
  const authResult = await authorizeGatewayConnect({
    auth: opts.auth,
    connectAuth: { token, password: token },
    req,
    trustedProxies: opts.trustedProxies,
  });
  if (!authResult.ok) {
    sendUnauthorized(res);
    return true;
  }

  // Route dispatch
  const path = url.pathname;

  // POST /api/login — auto-succeed
  if (path === "/api/login" && req.method === "POST") {
    // Consume body
    await readJsonBodyOrError(req, res, 4096);
    sendJson(res, 200, {
      id: 1,
      username: "user",
      name: "User",
      organisation_id: 1,
      organisation: {
        id: 1,
        name: "Default",
        slug: "default",
        created_at: new Date().toISOString(),
      },
      teams: [],
      created_at: new Date().toISOString(),
    });
    return true;
  }

  // GET /api/users/:id
  const userMatch = path.match(/^\/api\/users\/(\d+)$/);
  if (userMatch && req.method === "GET") {
    sendJson(res, 200, {
      id: parseInt(userMatch[1]!, 10),
      username: "user",
      name: "User",
      organisation_id: 1,
      organisation: {
        id: 1,
        name: "Default",
        slug: "default",
        created_at: new Date().toISOString(),
      },
      teams: [],
      created_at: new Date().toISOString(),
    });
    return true;
  }

  // GET /api/agents
  if (path === "/api/agents" && req.method === "GET") {
    sendJson(res, 200, [defaultAgent()]);
    return true;
  }

  // GET /api/agents/:slug
  const agentMatch = path.match(/^\/api\/agents\/([^/]+)$/);
  if (agentMatch && req.method === "GET") {
    sendJson(res, 200, defaultAgent());
    return true;
  }

  // GET /api/users/:id/conversations
  const userConvsMatch = path.match(/^\/api\/users\/\d+\/conversations$/);
  if (userConvsMatch && req.method === "GET") {
    return handleListConversations(res, url);
  }

  // POST /api/users/:id/conversations
  if (userConvsMatch && req.method === "POST") {
    return handleCreateConversation(req, res);
  }

  // GET/PUT/DELETE /api/conversations/:id/plan
  const planMatch = path.match(/^\/api\/conversations\/([^/]+)\/plan$/);
  if (planMatch) {
    const conversationId = decodeURIComponent(planMatch[1]!);
    if (req.method === "GET") return handleGetPlan(res, conversationId);
    if (req.method === "PUT") return handleSavePlan(req, res, conversationId);
    if (req.method === "DELETE") return handleDeletePlan(res, conversationId);
    sendMethodNotAllowed(res);
    return true;
  }

  // GET/PUT/DELETE /api/conversations/:id
  const convMatch = path.match(/^\/api\/conversations\/(.+)$/);
  if (convMatch) {
    const conversationId = decodeURIComponent(convMatch[1]!);
    if (req.method === "GET") return handleGetConversation(res, conversationId);
    if (req.method === "PUT") return handleUpdateConversation(req, res, conversationId);
    if (req.method === "DELETE") return handleDeleteConversation(res, conversationId);
    sendMethodNotAllowed(res);
    return true;
  }

  // Not matched
  return false;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

function handleListConversations(res: ServerResponse, url: URL): boolean {
  const cfg = loadConfig();
  const { storePath, store } = loadCombinedSessionStoreForGateway(cfg);

  const result = listSessionsFromStore({
    cfg,
    storePath,
    store,
    opts: {
      includeDerivedTitles: true,
      includeLastMessage: true,
      limit: 100,
    },
  });

  // Filter to openresponses sessions only
  const conversations: ApiConversation[] = result.sessions
    .filter((s) => s.key.includes("openresponses"))
    .map((s) =>
      sessionKeyToConversation(s.key, {
        updatedAt: s.updatedAt ?? undefined,
        displayName: s.displayName ?? undefined,
        label: s.label ?? undefined,
        derivedTitle: s.derivedTitle ?? undefined,
      }),
    );

  sendJson(res, 200, conversations);
  return true;
}

async function handleCreateConversation(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const body = await readJsonBodyOrError(req, res, 4096);
  if (body === undefined) return true;

  // Generate a new openresponses session key
  const sessionKey = `agent:main:openresponses:${randomUUID()}`;
  const now = new Date().toISOString();

  const conversation: ApiConversation = {
    id: sessionKey,
    session_id: sessionKey,
    title: ((body as Record<string, unknown>).title as string) || "New conversation",
    user_id: 1,
    agent_id: 1,
    agent: defaultAgent(),
    created_at: now,
    updated_at: now,
  };

  sendJson(res, 201, conversation);
  return true;
}

function handleGetConversation(res: ServerResponse, conversationId: string): boolean {
  const cfg = loadConfig();
  const target = resolveGatewaySessionStoreTarget({ cfg, key: conversationId });
  const store = loadSessionStore(target.storePath);
  const entry =
    target.storeKeys.map((candidate) => store[candidate]).find(Boolean) ??
    store[target.canonicalKey];

  const updatedAt = entry?.updatedAt
    ? new Date(entry.updatedAt).toISOString()
    : new Date().toISOString();

  // Load messages from transcript
  let messages: ApiMessage[] = [];
  if (entry?.sessionId) {
    const items = readSessionPreviewItemsFromTranscript(
      entry.sessionId,
      target.storePath,
      entry.sessionFile,
      target.agentId,
      100, // generous limit for full conversation view
      50000, // don't truncate message text aggressively
    );
    messages = previewItemsToMessages(items, updatedAt);
  }

  // Derive title from first user message
  const firstUserMsg = messages.find((m) => m.sender === "user");
  const title = entry?.displayName ?? firstUserMsg?.text?.slice(0, 60) ?? conversationId;

  const detail: ApiConversationDetail = {
    id: conversationId,
    session_id: conversationId,
    title,
    user_id: 1,
    agent_id: 1,
    agent: defaultAgent(),
    created_at: updatedAt,
    updated_at: updatedAt,
    messages,
  };

  sendJson(res, 200, detail);
  return true;
}

async function handleUpdateConversation(
  req: IncomingMessage,
  res: ServerResponse,
  conversationId: string,
): Promise<boolean> {
  const body = await readJsonBodyOrError(req, res, 4096);
  if (body === undefined) return true;

  const title = (body as Record<string, unknown>).title as string | undefined;

  // Update displayName in session store
  if (title) {
    const cfg = loadConfig();
    const target = resolveGatewaySessionStoreTarget({ cfg, key: conversationId });
    await updateSessionStore(target.storePath, (store) => {
      const storeKey = target.storeKeys.find((k) => store[k]) ?? target.canonicalKey;
      const entry = store[storeKey];
      if (entry) {
        entry.displayName = title;
      }
    });
  }

  const now = new Date().toISOString();
  sendJson(res, 200, {
    id: conversationId,
    session_id: conversationId,
    title: title ?? conversationId,
    user_id: 1,
    agent_id: 1,
    agent: defaultAgent(),
    created_at: now,
    updated_at: now,
  });
  return true;
}

// ---------------------------------------------------------------------------
// Plans storage
// ---------------------------------------------------------------------------

function getPlansDir(): string {
  const dir = nodePath.join(os.homedir(), ".clawdbot-dev", "plans");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function planFilePath(conversationId: string): string {
  // Sanitize the key for filesystem use
  const safe = conversationId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return nodePath.join(getPlansDir(), `${safe}.json`);
}

function handleGetPlan(res: ServerResponse, conversationId: string): boolean {
  const filePath = planFilePath(conversationId);
  try {
    if (!fs.existsSync(filePath)) {
      sendJson(res, 200, null);
      return true;
    }
    const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    sendJson(res, 200, data);
  } catch {
    sendJson(res, 200, null);
  }
  return true;
}

async function handleSavePlan(
  req: IncomingMessage,
  res: ServerResponse,
  conversationId: string,
): Promise<boolean> {
  const body = await readJsonBodyOrError(req, res, 64 * 1024);
  if (body === undefined) return true;

  const payload = body as Record<string, unknown>;
  const now = new Date().toISOString();
  const planData = {
    id: 1,
    conversation_id: conversationId,
    strategy: payload.strategy ?? "orchestrated",
    content: payload.content ?? {},
    created_at: now,
    updated_at: now,
  };

  const filePath = planFilePath(conversationId);
  // Merge with existing if present
  try {
    if (fs.existsSync(filePath)) {
      const existing = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      planData.created_at = existing.created_at || now;
      planData.id = existing.id || 1;
    }
  } catch {
    /* ignore */
  }

  fs.writeFileSync(filePath, JSON.stringify(planData, null, 2));
  sendJson(res, 200, planData);
  return true;
}

async function handleDeletePlan(res: ServerResponse, conversationId: string): Promise<boolean> {
  const filePath = planFilePath(conversationId);
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    /* ignore */
  }
  sendJson(res, 200, { ok: true });
  return true;
}

async function handleDeleteConversation(
  res: ServerResponse,
  conversationId: string,
): Promise<boolean> {
  const cfg = loadConfig();
  const target = resolveGatewaySessionStoreTarget({ cfg, key: conversationId });
  await updateSessionStore(target.storePath, (store) => {
    const storeKey = target.storeKeys.find((k) => store[k]) ?? target.canonicalKey;
    if (store[storeKey]) {
      delete store[storeKey];
    }
  });

  sendJson(res, 200, { ok: true });
  return true;
}
