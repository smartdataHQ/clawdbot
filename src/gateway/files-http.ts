/**
 * File management HTTP endpoints for OpenResponses integration.
 *
 * Provides /v1/files/* endpoints for listing, uploading, downloading,
 * and deleting files in the agent workspace.
 */

import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import { pipeline } from "node:stream/promises";
import { Writable } from "node:stream";

import { loadConfig } from "../config/config.js";
import { resolveAgentWorkspaceDir } from "../agents/agent-scope.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";
import { getBearerToken, resolveAgentIdForRequest } from "./http-utils.js";
import { sendJson, sendMethodNotAllowed, sendText, sendUnauthorized } from "./http-common.js";

// ---------------------------------------------------------------------------
// Chunked upload state
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 1024 * 1024; // 1MB default

interface PendingUpload {
  uploadId: string;
  sessionId: string;
  files: Array<{
    filename: string;
    size: number;
    mimeType: string;
    relativePath: string;
  }>;
  receivedChunks: Set<number>;
  totalChunks: number;
  chunkSize: number;
  tempDir: string;
  createdAt: number;
}

const pendingUploads = new Map<string, PendingUpload>();

function getUploadsTempBase(): string {
  const devDir = path.join(os.homedir(), ".clawdbot-dev", "files", "uploads");
  fs.mkdirSync(devDir, { recursive: true });
  return devDir;
}

export interface FilesHttpOptions {
  auth: ResolvedGatewayAuth;
  trustedProxies?: string[];
}

function resolveWorkspace(agentId: string): string {
  const cfg = loadConfig();
  return resolveAgentWorkspaceDir(cfg, agentId);
}

/** Ensure resolved path stays within workspace */
function safePath(workspace: string, relativePath: string): string | null {
  const resolved = path.resolve(workspace, relativePath.replace(/^\/+/, ""));
  if (!resolved.startsWith(workspace)) return null;
  return resolved;
}

function mimeFromExt(filePath: string): string | null {
  const ext = path.extname(filePath).toLowerCase();
  const map: Record<string, string> = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".js": "application/javascript",
    ".ts": "text/typescript",
    ".html": "text/html",
    ".css": "text/css",
    ".csv": "text/csv",
    ".xml": "text/xml",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".py": "text/x-python",
    ".sh": "text/x-shellscript",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
  };
  return map[ext] ?? null;
}

async function listFiles(
  workspace: string,
  subPath: string,
): Promise<
  Array<{
    name: string;
    path: string;
    size: number;
    is_dir: boolean;
    modified_at: string;
    mime_type: string | null;
  }>
> {
  const resolved = safePath(workspace, subPath || ".");
  if (!resolved) return [];

  try {
    const entries = await fs.promises.readdir(resolved, { withFileTypes: true });
    const results = [];
    for (const entry of entries) {
      // Skip hidden files and common noise
      if (entry.name.startsWith(".")) continue;
      if (entry.name === "node_modules") continue;

      const fullPath = path.join(resolved, entry.name);
      const relativePath = path.relative(workspace, fullPath);
      try {
        const stat = await fs.promises.stat(fullPath);
        results.push({
          name: entry.name,
          path: relativePath,
          size: stat.size,
          is_dir: entry.isDirectory(),
          modified_at: stat.mtime.toISOString(),
          mime_type: entry.isDirectory() ? null : mimeFromExt(entry.name),
        });
      } catch {
        // Skip files we can't stat
      }
    }
    return results.sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  } catch {
    return [];
  }
}

async function readRawBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let totalSize = 0;
  for await (const chunk of req) {
    totalSize += chunk.length;
    if (totalSize > maxBytes) throw new Error("Body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function handleFilesHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: FilesHttpOptions,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);
  // Accept both /v1/files/* and /files/* (baseline frontend uses /files/*)
  if (!url.pathname.startsWith("/v1/files/") && !url.pathname.startsWith("/files/")) return false;

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

  const agentId = resolveAgentIdForRequest({ req, model: "default" });
  const workspace = resolveWorkspace(agentId);

  // Strip prefix: /v1/files/ or /files/
  const endpoint = url.pathname.startsWith("/v1/files/")
    ? url.pathname.replace("/v1/files/", "")
    : url.pathname.replace("/files/", "");

  // GET /v1/files/list
  if (endpoint === "list" && (req.method === "GET" || req.method === "POST")) {
    let subPath = ".";
    if (req.method === "POST") {
      try {
        const raw = await readRawBody(req, 1024 * 10);
        const body = JSON.parse(raw.toString("utf-8"));
        subPath = body.path || ".";
      } catch {
        /* use default */
      }
    } else {
      subPath = url.searchParams.get("path") || ".";
    }

    // Normalize: strip leading /workspace/ prefix that frontend sends
    subPath = subPath.replace(/^\/workspace\/?/, "");

    const files = await listFiles(workspace, subPath);
    sendJson(res, 200, { files, workspace_root: workspace });
    return true;
  }

  // POST /files/upload/init — chunked upload initialization
  if (endpoint === "upload/init" && req.method === "POST") {
    try {
      const raw = await readRawBody(req, 1024 * 64);
      const body = JSON.parse(raw.toString("utf-8"));
      const sessionId = (body.session_id as string) || "";
      const filesArr =
        (body.files as Array<{
          filename: string;
          size?: number;
          relative_path?: string;
          mime_type?: string;
        }>) || [];

      if (filesArr.length === 0) {
        sendJson(res, 400, { error: "No files specified" });
        return true;
      }

      const uploads: Array<{
        upload_id: string;
        chunk_size: number;
        total_chunks: number;
      }> = [];

      for (const f of filesArr) {
        const uploadId = randomUUID();
        const fileSize = f.size || 0;
        const totalChunks = fileSize > 0 ? Math.ceil(fileSize / CHUNK_SIZE) : 1;
        const tempDir = path.join(getUploadsTempBase(), uploadId);
        fs.mkdirSync(tempDir, { recursive: true });

        pendingUploads.set(uploadId, {
          uploadId,
          sessionId,
          files: [
            {
              filename: f.filename,
              size: fileSize,
              mimeType: f.mime_type || "application/octet-stream",
              relativePath: f.relative_path || "",
            },
          ],
          receivedChunks: new Set(),
          totalChunks,
          chunkSize: CHUNK_SIZE,
          tempDir,
          createdAt: Date.now(),
        });

        uploads.push({
          upload_id: uploadId,
          chunk_size: CHUNK_SIZE,
          total_chunks: totalChunks,
        });
      }

      sendJson(res, 200, { uploads });
    } catch (err) {
      sendJson(res, 500, { error: String(err) });
    }
    return true;
  }

  // POST /files/upload/:id/chunk — receive a chunk
  const chunkMatch = endpoint.match(/^upload\/([^/]+)\/chunk$/);
  if (chunkMatch && req.method === "POST") {
    const uploadId = chunkMatch[1]!;
    const pending = pendingUploads.get(uploadId);
    if (!pending) {
      sendJson(res, 404, { error: "Upload not found" });
      return true;
    }

    try {
      const raw = await readRawBody(req, CHUNK_SIZE + 1024 * 64);
      const contentType = req.headers["content-type"] || "";

      let chunkIndex = 0;
      let chunkData: Buffer;

      if (contentType.includes("multipart/form-data")) {
        // Parse multipart: extract chunk_index and file data
        // Simple boundary-based parser
        const boundary = contentType.split("boundary=")[1]?.split(";")[0]?.trim();
        if (!boundary) {
          sendJson(res, 400, { error: "Missing boundary" });
          return true;
        }
        const parts = parseMultipart(raw, boundary);
        const indexPart = parts.find((p) => p.name === "chunk_index");
        const filePart = parts.find((p) => p.name === "file");
        chunkIndex = indexPart ? parseInt(indexPart.data.toString("utf-8"), 10) : 0;
        chunkData = filePart?.data ?? raw;
      } else {
        // Raw binary, chunk index from query
        chunkIndex = parseInt(
          url.searchParams.get("offset") || url.searchParams.get("chunk_index") || "0",
          10,
        );
        chunkData = raw;
      }

      const chunkPath = path.join(pending.tempDir, `chunk_${chunkIndex}`);
      await fs.promises.writeFile(chunkPath, chunkData);
      pending.receivedChunks.add(chunkIndex);

      sendJson(res, 200, { received: pending.receivedChunks.size });
    } catch (err) {
      sendJson(res, 500, { error: String(err) });
    }
    return true;
  }

  // POST /files/upload/:id/complete — finalize chunked upload
  const completeMatch = endpoint.match(/^upload\/([^/]+)\/complete$/);
  if (completeMatch && req.method === "POST") {
    const uploadId = completeMatch[1]!;
    const pending = pendingUploads.get(uploadId);
    if (!pending) {
      sendJson(res, 404, { error: "Upload not found" });
      return true;
    }

    try {
      const fileInfo = pending.files[0];
      if (!fileInfo) {
        sendJson(res, 400, { error: "No file info" });
        return true;
      }

      // Reassemble chunks
      const chunks: Buffer[] = [];
      for (let i = 0; i < pending.totalChunks; i++) {
        const chunkPath = path.join(pending.tempDir, `chunk_${i}`);
        if (!fs.existsSync(chunkPath)) {
          sendJson(res, 400, { error: `Missing chunk ${i}` });
          return true;
        }
        chunks.push(await fs.promises.readFile(chunkPath));
      }
      const assembled = Buffer.concat(chunks);

      // Write to workspace
      const relDir = fileInfo.relativePath
        ? fileInfo.relativePath.replace(/^\/workspace\/?/, "")
        : ".";
      const resolved = safePath(workspace, path.join(relDir, fileInfo.filename));
      if (!resolved) {
        sendJson(res, 400, { error: "Invalid path" });
        return true;
      }

      await fs.promises.mkdir(path.dirname(resolved), { recursive: true });
      await fs.promises.writeFile(resolved, assembled);

      // Cleanup temp
      await fs.promises.rm(pending.tempDir, { recursive: true, force: true });
      pendingUploads.delete(uploadId);

      const stat = await fs.promises.stat(resolved);
      const relativePath = path.relative(workspace, resolved);

      sendJson(res, 200, {
        success: true,
        file: {
          name: fileInfo.filename,
          path: relativePath,
          size: stat.size,
          is_dir: false,
          modified_at: stat.mtime.toISOString(),
          mime_type: mimeFromExt(fileInfo.filename) || fileInfo.mimeType,
        },
      });
    } catch (err) {
      sendJson(res, 500, { error: String(err) });
    }
    return true;
  }

  // POST /v1/files/upload
  if (endpoint === "upload" && req.method === "POST") {
    const contentType = req.headers["content-type"] || "";

    // Handle multipart (simplified — single file with filename header)
    // For now, support JSON body with base64 data
    try {
      const raw = await readRawBody(req, 50 * 1024 * 1024);

      if (contentType.includes("application/json")) {
        const body = JSON.parse(raw.toString("utf-8"));
        const filename = body.filename as string;
        const data = body.data as string; // base64
        const targetPath = body.path as string | undefined;

        if (!filename || !data) {
          sendJson(res, 400, { error: "filename and data (base64) required" });
          return true;
        }

        const relDir = targetPath ? targetPath.replace(/^\/workspace\/?/, "") : ".";
        const resolved = safePath(workspace, path.join(relDir, filename));
        if (!resolved) {
          sendJson(res, 400, { error: "Invalid path" });
          return true;
        }

        await fs.promises.mkdir(path.dirname(resolved), { recursive: true });
        await fs.promises.writeFile(resolved, Buffer.from(data, "base64"));

        const stat = await fs.promises.stat(resolved);
        const relativePath = path.relative(workspace, resolved);

        sendJson(res, 200, {
          success: true,
          file: {
            name: filename,
            path: relativePath,
            size: stat.size,
            is_dir: false,
            modified_at: stat.mtime.toISOString(),
            mime_type: mimeFromExt(filename),
          },
        });
      } else {
        // Raw binary upload — filename from query or header
        const filename =
          url.searchParams.get("filename") ||
          (req.headers["x-filename"] as string) ||
          `upload-${randomUUID()}`;
        const targetPath = url.searchParams.get("path") || ".";
        const relDir = targetPath.replace(/^\/workspace\/?/, "");
        const resolved = safePath(workspace, path.join(relDir, filename));
        if (!resolved) {
          sendJson(res, 400, { error: "Invalid path" });
          return true;
        }

        await fs.promises.mkdir(path.dirname(resolved), { recursive: true });
        await fs.promises.writeFile(resolved, raw);

        const stat = await fs.promises.stat(resolved);
        const relativePath = path.relative(workspace, resolved);

        sendJson(res, 200, {
          success: true,
          file: {
            name: filename,
            path: relativePath,
            size: stat.size,
            is_dir: false,
            modified_at: stat.mtime.toISOString(),
            mime_type: mimeFromExt(filename),
          },
        });
      }
    } catch (err) {
      sendJson(res, 500, { error: String(err) });
    }
    return true;
  }

  // POST /v1/files/download
  if (endpoint === "download" && req.method === "POST") {
    try {
      const raw = await readRawBody(req, 1024 * 10);
      const body = JSON.parse(raw.toString("utf-8"));
      const filePath = (body.path as string) || "";

      const resolved = safePath(workspace, filePath.replace(/^\/workspace\/?/, ""));
      if (!resolved || !fs.existsSync(resolved)) {
        sendJson(res, 404, { error: "File not found" });
        return true;
      }

      const stat = await fs.promises.stat(resolved);
      if (stat.isDirectory()) {
        sendJson(res, 400, { error: "Cannot download directory" });
        return true;
      }

      const mime = mimeFromExt(resolved) || "application/octet-stream";
      const filename = path.basename(resolved);
      res.setHeader("Content-Type", mime);
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", stat.size);
      res.statusCode = 200;

      const readStream = fs.createReadStream(resolved);
      await pipeline(readStream, res);
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, 500, { error: String(err) });
      }
    }
    return true;
  }

  // POST /v1/files/delete
  if (endpoint === "delete" && req.method === "POST") {
    try {
      const raw = await readRawBody(req, 1024 * 10);
      const body = JSON.parse(raw.toString("utf-8"));
      const paths = (body.paths as string[]) || [];

      const deleted: string[] = [];
      const errors: string[] = [];

      for (const p of paths) {
        const cleaned = p.replace(/^\/workspace\/?/, "");
        const resolved = safePath(workspace, cleaned);
        if (!resolved) {
          errors.push(`Invalid path: ${p}`);
          continue;
        }
        try {
          await fs.promises.rm(resolved, { recursive: true });
          deleted.push(cleaned);
        } catch (err) {
          errors.push(`${p}: ${String(err)}`);
        }
      }

      sendJson(res, 200, { deleted, errors, success: deleted.length > 0 });
    } catch (err) {
      sendJson(res, 500, { error: String(err) });
    }
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Simple multipart/form-data parser
// ---------------------------------------------------------------------------

interface MultipartPart {
  name: string;
  filename?: string;
  data: Buffer;
}

function parseMultipart(body: Buffer, boundary: string): MultipartPart[] {
  const parts: MultipartPart[] = [];
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const endBuf = Buffer.from(`--${boundary}--`);

  let pos = 0;
  // Find first boundary
  let idx = body.indexOf(boundaryBuf, pos);
  if (idx < 0) return parts;
  pos = idx + boundaryBuf.length;

  while (pos < body.length) {
    // Skip CRLF after boundary
    if (body[pos] === 0x0d && body[pos + 1] === 0x0a) pos += 2;

    // Check for end boundary
    if (body.subarray(pos - boundaryBuf.length - 2, pos).indexOf(endBuf) >= 0) break;

    // Read headers until double CRLF
    const headerEnd = body.indexOf(Buffer.from("\r\n\r\n"), pos);
    if (headerEnd < 0) break;

    const headerStr = body.subarray(pos, headerEnd).toString("utf-8");
    pos = headerEnd + 4;

    // Find next boundary
    const nextBoundary = body.indexOf(boundaryBuf, pos);
    const dataEnd = nextBoundary >= 0 ? nextBoundary - 2 : body.length; // -2 for CRLF before boundary
    const data = body.subarray(pos, dataEnd);
    pos = nextBoundary >= 0 ? nextBoundary + boundaryBuf.length : body.length;

    // Parse name from Content-Disposition
    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);

    if (nameMatch) {
      parts.push({
        name: nameMatch[1]!,
        filename: filenameMatch?.[1],
        data,
      });
    }
  }

  return parts;
}
