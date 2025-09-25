import "dotenv/config";
import http from "node:http";
import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { AppleMusicAPI } from "./appleMusic/api.js";
import {
  createDeveloperTokenProvider,
  getDeveloperConfigFromEnv,
  getMusicUserToken,
  setMusicUserToken,
} from "./auth/appleMusicAuth.js";
// OAuth helpers will be implemented inline in this file for stateless mode

const serverName = "applemusic-mcp";

const mcpServer = new McpServer(
  {
    name: serverName,
    version: "0.1.0",
  },
  {
    instructions:
      "Apple Music MCP: authenticate, search catalog, fetch metadata, manage your library and playlists, and fetch Replay.",
    capabilities: {
      tools: {},
      logging: {},
    },
  },
);

// Session token store - maps MCP session ID to Music User Token
const sessionTokens = new Map<string, string>();
let pendingToken: string | undefined;

// Instantiate Apple Music API with OAuth-aware user token getter
const getDevToken = createDeveloperTokenProvider();
const api = new AppleMusicAPI({ 
  getDeveloperToken: getDevToken,
  getUserToken: () => {
    // First try in-memory token
    const memToken = getMusicUserToken();
    if (memToken) return memToken;
    return undefined;
  },
  // Stateless mode: tokens are provided per-request by the client via Authorization header
});

// =====================
// OAuth (stateless) helpers
// =====================

function getOAuthMetadata(baseUrl: string) {
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    response_types_supported: ["code"],
    response_modes_supported: ["query", "fragment"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["music.library.read", "music.library.write"],
  } as const;
}

const handleOAuthAuthorize = async (
  _req: http.IncomingMessage,
  res: http.ServerResponse,
  searchParams: URLSearchParams,
) => {
  const redirectUri = searchParams.get("redirect_uri");
  const state = searchParams.get("state");
  if (!redirectUri || !state) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Missing redirect_uri or state");
    return;
  }

  // Get developer token for MusicKit JS
  const developerToken = await getDevToken();

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Apple Music Authorization</title>
  <script src="https://js-cdn.music.apple.com/musickit/v3/musickit.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f5f5f7; }
    .container { text-align: center; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 420px; }
    h1 { font-size: 22px; margin-bottom: 16px; }
    p { color: #666; margin-bottom: 24px; }
    button { background: #fc3c44; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
    button:hover { background: #e5353c; }
    .error { color: #d60017; margin-top: 16px; }
    .success { color: #28a745; margin-top: 16px; }
  </style>
<body>
  <div class="container">
    <h1>Connect Apple Music</h1>
    <p>Authorize access to your Apple Music library.</p>
    <button id="authBtn" onclick="authorize()">Authorize</button>
    <div id="status"></div>
  </div>
  <script>
    const redirectUri = ${JSON.stringify(redirectUri)};
    const state = ${JSON.stringify(state)};
    const developerToken = ${JSON.stringify(developerToken)};

    async function authorize() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.textContent = 'Authorizing...';
      try {
        await MusicKit.configure({ developerToken, app: { name: 'Apple Music MCP', build: '1.0.0' } });
        const music = MusicKit.getInstance();
        const musicUserToken = await music.authorize();

        status.textContent = 'Authorized. Redirecting...';
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/oauth/callback';
        const t = document.createElement('input'); t.type='hidden'; t.name='music_user_token'; t.value = musicUserToken; form.appendChild(t);
        const s = document.createElement('input'); s.type='hidden'; s.name='state'; s.value = state; form.appendChild(s);
        const r = document.createElement('input'); r.type='hidden'; r.name='redirect_uri'; r.value = redirectUri; form.appendChild(r);
        document.body.appendChild(form);
        form.submit();
      } catch (err) {
        btn.disabled = false;
        status.innerHTML = '<span class="error">' + (err?.message || 'Authorization failed') + '</span>';
      }
    }
  </script>
</body>
</html>`;

  res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" });
  res.end(html);
};

const handleOAuthCallback = async (
  _req: http.IncomingMessage,
  res: http.ServerResponse,
  body: string,
) => {
  const params = new URLSearchParams(body);
  const token = params.get("music_user_token");
  const state = params.get("state");
  const redirectUri = params.get("redirect_uri");
  if (!token || !state || !redirectUri) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Missing parameters");
    return;
  }
  const url = new URL(redirectUri);
  url.searchParams.set("code", token);
  url.searchParams.set("state", state);
  res.writeHead(302, { Location: url.toString(), "cache-control": "no-store" });
  res.end();
};

const handleOAuthToken = async (
  _req: http.IncomingMessage,
  res: http.ServerResponse,
  body: string,
) => {
  const params = new URLSearchParams(body);
  const grantType = params.get("grant_type");
  const code = params.get("code");
  if (grantType !== "authorization_code" || !code) {
    res.writeHead(400, { 
      "content-type": "application/json", 
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    });
    res.end(JSON.stringify({ error: "invalid_request" }));
    return;
  }
  const response = {
    access_token: code, // Stateless: client will present this Bearer token on each request
    token_type: "Bearer",
    expires_in: 60 * 60 * 24 * 90, // 90 days (hint only; no server-side state)
    scope: "music.library.read music.library.write",
  } as const;
  res.writeHead(200, { 
    "content-type": "application/json", 
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  res.end(JSON.stringify(response));
};

// Auth tools
const setTokenSchema = z.object({
  musicUserToken: z.string().min(10).describe("Apple Music Music User Token"),
});
mcpServer.registerTool(
  "applemusic.auth.set_user_token",
  {
    title: "Set Music User Token",
    description: "Sets the user token required for library operations.",
    inputSchema: setTokenSchema.shape,
  },
  async ({ musicUserToken }: z.infer<typeof setTokenSchema>) => {
    setMusicUserToken(musicUserToken);
    return { content: [{ type: "text", text: "Music User Token set." }] };
  },
);

mcpServer.registerTool(
  "applemusic.auth.status",
  {
    title: "Auth Status",
    description: "Returns whether developer credentials and user token are set (checks Authorization header and in-memory).",
  },
  async (_args, extra) => {
    let devOk = false;
    try {
      getDeveloperConfigFromEnv();
      await getDevToken();
      devOk = true;
    } catch {}


    const inMemoryToken = Boolean(getMusicUserToken());
    const sessionId = resolveSessionId(extra);
    const sessionToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const hasSession = Boolean(sessionToken);
    const hasUser = inMemoryToken || hasSession;
    
    // Debug session info
    console.log("=== Auth Status Debug ===");
    console.log("Session ID from extra:", extra?.sessionId);
    console.log("Session ID resolved:", sessionId);
    console.log("Session token found:", hasSession);
    console.log("All stored sessions:", Array.from(sessionTokens.keys()));
    console.log("=========================");

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              developerConfigured: devOk,
              hasMusicUserToken: hasUser,
              authSources: {
                session: hasSession,
                manual: inMemoryToken,
              },
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// Catalog tools
const catalogSearchSchema = z.object({
  term: z.string().min(1),
  types: z.string().optional().describe("Comma-separated types e.g., songs,albums,artists"),
  storefront: z.string().optional(),
  limit: z.number().int().min(1).max(50).optional(),
});
mcpServer.registerTool(
  "applemusic.catalog.search",
  {
    title: "Catalog Search",
    description: "Search Apple Music catalog.",
    inputSchema: catalogSearchSchema.shape,
  },
  async (args: z.infer<typeof catalogSearchSchema>) => {
    const data = await api.searchCatalog(args);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const catalogSongSchema = z.object({ id: z.string().min(1), storefront: z.string().optional() });
mcpServer.registerTool(
  "applemusic.catalog.song",
  { title: "Get Song", description: "Get catalog song by id.", inputSchema: catalogSongSchema.shape },
  async (args: z.infer<typeof catalogSongSchema>) => {
    const data = await api.getSong(args);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const catalogSongsByIsrcSchema = z.object({ isrc: z.string().min(3), storefront: z.string().optional() });
mcpServer.registerTool(
  "applemusic.catalog.songs_by_isrc",
  { title: "Get Songs by ISRC", description: "Find catalog songs by ISRC.", inputSchema: catalogSongsByIsrcSchema.shape },
  async (args: z.infer<typeof catalogSongsByIsrcSchema>) => {
    const data = await api.getSongsByIsrc(args);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

// Library tools
const listLibrarySongsSchema = z.object({ limit: z.number().int().min(1).max(100).optional(), offset: z.string().optional() });
mcpServer.registerTool(
  "applemusic.library.songs",
  { title: "List Library Songs", description: "List user's library songs.", inputSchema: listLibrarySongsSchema.shape },
  async (args: z.infer<typeof listLibrarySongsSchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.listLibrarySongs(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const searchLibrarySchema = z.object({ term: z.string().min(1), types: z.string().optional(), limit: z.number().int().min(1).max(50).optional() });
mcpServer.registerTool(
  "applemusic.library.search",
  { title: "Search Library", description: "Search user's library.", inputSchema: searchLibrarySchema.shape },
  async (args: z.infer<typeof searchLibrarySchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.searchLibrary(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const listPlaylistsSchema = z.object({ limit: z.number().int().min(1).max(100).optional(), offset: z.string().optional() });
mcpServer.registerTool(
  "applemusic.library.playlists",
  { title: "List Playlists", description: "List user's library playlists.", inputSchema: listPlaylistsSchema.shape },
  async (args: z.infer<typeof listPlaylistsSchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.listLibraryPlaylists(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const playlistTracksSchema = z.object({ id: z.string().min(1), limit: z.number().int().min(1).max(100).optional(), offset: z.string().optional() });
mcpServer.registerTool(
  "applemusic.library.playlist_tracks",
  { title: "Playlist Tracks", description: "List tracks in a user's playlist.", inputSchema: playlistTracksSchema.shape },
  async (args: z.infer<typeof playlistTracksSchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.getPlaylistTracks(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const addToLibraryInputShape = {
  songIds: z.array(z.string()).optional(),
  albumIds: z.array(z.string()).optional(),
};
const addToLibrarySchema = z
  .object(addToLibraryInputShape)
  .refine((v) => (v.songIds && v.songIds.length) || (v.albumIds && v.albumIds.length), {
    message: "Provide songIds or albumIds",
  });
mcpServer.registerTool(
  "applemusic.library.add",
  {
    title: "Add to Library",
    description: "Add songs or albums to user's library.",
    inputSchema: addToLibraryInputShape,
  },
  async (args: z.infer<typeof addToLibrarySchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.addToLibrary(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const createPlaylistSchema = z.object({ name: z.string().min(1), description: z.string().optional(), trackIds: z.array(z.string()).optional() });
mcpServer.registerTool(
  "applemusic.library.playlists.create",
  { title: "Create Playlist", description: "Create a new playlist in user's library.", inputSchema: createPlaylistSchema.shape },
  async (args: z.infer<typeof createPlaylistSchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.createPlaylist(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const addTracksSchema = z.object({ playlistId: z.string().min(1), trackIds: z.array(z.string()).min(1) });
mcpServer.registerTool(
  "applemusic.library.playlists.add_tracks",
  { title: "Add Tracks to Playlist", description: "Append tracks to a user's playlist.", inputSchema: addTracksSchema.shape },
  async (args: z.infer<typeof addTracksSchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.addTracksToPlaylist(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

// Replay
const replaySchema = z.object({ year: z.number().int().optional() });
mcpServer.registerTool(
  "applemusic.replay.get",
  { title: "Get Replay", description: "Fetch Apple Music Replay data for the user.", inputSchema: replaySchema.shape },
  async (args: z.infer<typeof replaySchema>, extra) => {
    const sessionId = resolveSessionId(extra);
    const userToken = sessionId ? sessionTokens.get(sessionId) : pendingToken;
    const data = await api.getReplay(args, userToken);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

function parseBearerToken(authHeader?: string): string | undefined {
  if (!authHeader) return undefined;
  const [scheme, value] = authHeader.split(" ");
  if (!scheme || !value) return undefined;
  if (scheme.toLowerCase() !== "bearer") return undefined;
  return value.trim();
}

function getBearerFromHeaders(
  headers?: Record<string, string | string[] | undefined>,
): string | undefined {
  if (!headers) return undefined;
  // Node normalizes incoming header names to lowercase; handle both just in case
  const candidates = [
    "authorization",
    "Authorization",
    "x-mcp-proxy-auth",
    "X-MCP-Proxy-Auth",
    "x-mcp-auth",
    "X-MCP-Auth",
    "mcp-authorization",
    "MCP-Authorization",
  ];
  for (const key of candidates) {
    const raw = headers[key as keyof typeof headers];
    if (Array.isArray(raw)) {
      for (const entry of raw) {
        const token = parseBearerToken(entry);
        if (token) return token;
      }
    } else if (typeof raw === "string") {
      const token = parseBearerToken(raw);
      if (token) return token;
    }
  }
  return undefined;
}

function getSessionIdFromHeaders(
  headers?: Record<string, string | string[] | undefined>,
): string | undefined {
  if (!headers) return undefined;
  const keys = ["mcp-session-id", "Mcp-Session-Id", "x-mcp-session-id", "X-MCP-Session-Id"];
  for (const key of keys) {
    const raw = headers[key as keyof typeof headers];
    if (Array.isArray(raw)) {
      for (const entry of raw) {
        if (entry) return entry;
      }
    } else if (typeof raw === "string" && raw.length > 0) {
      return raw;
    }
  }
  return undefined;
}

function resolveSessionId(extra?: {
  sessionId?: string;
  requestInfo?: { headers?: Record<string, string | string[] | undefined> };
}): string | undefined {
  if (extra?.sessionId) return extra.sessionId;
  return getSessionIdFromHeaders(extra?.requestInfo?.headers);
}

function getBaseUrlFromReq(req: http.IncomingMessage, fallbackPort: number): string {
  const forwardedProto = (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0]?.trim();
  const proto = forwardedProto || (req.headers["x-forwarded-proto"] ? "https" : "http");
  const forwardedHost = req.headers["x-forwarded-host"] as string | undefined;
  const host = forwardedHost || (req.headers.host ?? `localhost:${fallbackPort}`);
  return `${proto}://${host}`;
}

function stripMcpPrefix(pathname: string): string {
  return pathname.startsWith("/mcp/") ? pathname.slice(4) : pathname;
}

async function main() {
  const port = Number.parseInt(process.env.MCP_PORT ?? "3000", 10);
  const envBaseUrl = process.env.MCP_BASE_URL;
  const startupBaseUrl = envBaseUrl ?? `http://localhost:${port}`;
  console.log("[Startup] MCP_PORT=", port);
  console.log("[Startup] MCP_BASE_URL=", envBaseUrl ?? "<not set>");
  console.log("[Startup] base URL (capabilities)", startupBaseUrl);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
  });

  transport.onerror = (error: unknown) => {
    console.error("Transport error:", error);
  };

  // Register OAuth capabilities before connecting to transport
  const resourcePath = "/mcp";
  const authMetadataUrl = `${startupBaseUrl}/.well-known/oauth-authorization-server${resourcePath}`;
  mcpServer.server.registerCapabilities({
    experimental: {
      oauth: {
        authorizationUrl: authMetadataUrl,
        scopes: ["music.library.read", "music.library.write"],
      },
    },
  });

  await mcpServer.connect(transport);

  const server = http.createServer(async (req, res) => {
    const reqBase = getBaseUrlFromReq(req, port);
    const url = new URL(req.url || "/", reqBase);
    const effectiveBaseUrl = process.env.MCP_BASE_URL ?? reqBase;
    const rawPath = url.pathname;
    const path = stripMcpPrefix(rawPath);
    console.log("[HTTP]", req.method, rawPath, "=> path:", path, "base:", effectiveBaseUrl);
    
    // Handle OAuth endpoints (support both root and /mcp/ prefixed)
    if (path === "/oauth/authorize" && req.method === "GET") {
      try {
        console.log("[OAuth] authorize GET", { rawPath, base: effectiveBaseUrl });
        await handleOAuthAuthorize(req, res, url.searchParams);
      } catch (error) {
        console.error("OAuth authorize error:", error);
        res.writeHead(500, { 
          "content-type": "text/plain",
          "access-control-allow-origin": "*",
        });
        res.end("Internal server error");
      }
      return;
    }
    
    if (path === "/oauth/callback" && req.method === "POST") {
      try {
        console.log("[OAuth] callback POST", { rawPath });
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(chunk as Buffer);
        }
        const body = Buffer.concat(chunks).toString("utf8");
        await handleOAuthCallback(req, res, body);
      } catch (error) {
        console.error("OAuth callback error:", error);
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("Internal server error");
      }
      return;
    }
    
    if (path.startsWith("/.well-known/oauth-authorization-server") && req.method === "GET") {
      const basePath = "/.well-known/oauth-authorization-server";
      const suffix = path.length > basePath.length ? path.slice(basePath.length) : ""; // e.g. /mcp
      const issuer = suffix ? `${effectiveBaseUrl}${suffix}` : effectiveBaseUrl;
      console.log("[OAuth] metadata (RFC8414) GET", { rawPath, path, issuer });
      const metadata = getOAuthMetadata(issuer);
      res.writeHead(200, { 
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "cache-control": "public, max-age=3600", // Cache for 1 hour
      });
      res.end(JSON.stringify(metadata, null, 2));
      return;
    }
    // Also support OpenID configuration for compatibility
    if (path.startsWith("/.well-known/openid-configuration") && req.method === "GET") {
      const basePath = "/.well-known/openid-configuration";
      const suffix = path.length > basePath.length ? path.slice(basePath.length) : ""; // e.g. /mcp
      const issuer = suffix ? `${effectiveBaseUrl}${suffix}` : effectiveBaseUrl;
      console.log("[OIDC] openid-configuration GET", { rawPath, path, issuer });
      const md = getOAuthMetadata(issuer);
      // Map to OIDC-like fields for clients that probe this
      const oidc = {
        issuer: md.issuer,
        authorization_endpoint: md.authorization_endpoint,
        token_endpoint: md.token_endpoint,
        response_types_supported: md.response_types_supported,
        grant_types_supported: md.grant_types_supported,
        code_challenge_methods_supported: md.code_challenge_methods_supported,
        scopes_supported: md.scopes_supported,
      };
      res.writeHead(200, { 
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "cache-control": "public, max-age=3600",
      });
      res.end(JSON.stringify(oidc, null, 2));
      return;
    }

    // OAuth 2.0 Protected Resource Metadata (RFC9728)
    if (path.startsWith("/.well-known/oauth-protected-resource") && req.method === "GET") {
      const basePath = "/.well-known/oauth-protected-resource";
      const suffix = path.length > basePath.length ? path.slice(basePath.length) : ""; // e.g. /mcp
      const issuer = suffix ? `${effectiveBaseUrl}${suffix}` : effectiveBaseUrl;
      console.log("[PR] protected-resource GET", { rawPath, path, issuer });
      const authServers = [
        `${effectiveBaseUrl}`,
        `${effectiveBaseUrl}/mcp`,
      ];
      const pr = {
        resource: issuer,
        authorization_servers: Array.from(new Set(authServers)),
      } as const;
      res.writeHead(200, {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "cache-control": "public, max-age=3600",
      });
      res.end(JSON.stringify(pr, null, 2));
      return;
    }
    
    // Legacy metadata endpoint for backward compatibility
    if (path === "/mcp/oauth/metadata" && req.method === "GET") {
      const metadata = getOAuthMetadata(effectiveBaseUrl);
      res.writeHead(200, { 
        "content-type": "application/json",
        "access-control-allow-origin": "*",
      });
      res.end(JSON.stringify(metadata, null, 2));
      return;
    }
    
    if (path === "/oauth/token") {
      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "access-control-allow-origin": "*",
          "access-control-allow-headers": "content-type, authorization",
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-max-age": "86400",
        });
        res.end();
        return;
      }
      
      if (req.method === "POST") {
        try {
          console.log("[OAuth] token POST", { rawPath });
          const chunks: Buffer[] = [];
          for await (const chunk of req) {
            chunks.push(chunk as Buffer);
          }
          const body = Buffer.concat(chunks).toString("utf8");
          await handleOAuthToken(req, res, body);
        } catch (error) {
          console.error("OAuth token error:", error);
          res.writeHead(500, { 
            "content-type": "application/json",
            "access-control-allow-origin": "*",
            "cache-control": "no-store",
          });
          res.end(JSON.stringify({ error: "server_error" }));
        }
        return;
      }
    }
    
    // If this is an MCP request without Authorization, return WWW-Authenticate with resource metadata
    if (rawPath.startsWith("/mcp") && !req.headers.authorization) {
      const resource = `${effectiveBaseUrl}${resourcePath}`;
      const resourceMetadata = `${effectiveBaseUrl}/.well-known/oauth-protected-resource${resourcePath}`;
      const www = `Bearer realm="MCP", resource="${resource}", resource_metadata="${resourceMetadata}"`;
      console.log("[Auth] 401 WWW-Authenticate for MCP without token", { resource, resourceMetadata });
      res.writeHead(401, {
        "www-authenticate": www,
        "content-type": "application/json",
        "access-control-allow-origin": "*",
      });
      res.end(JSON.stringify({ error: "unauthorized", resource, resource_metadata: resourceMetadata }));
      return;
    }

    if (!req.url || !rawPath.startsWith("/mcp")) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32601,
            message: "Not Found",
          },
          id: null,
        }),
      );
      return;
    }

    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type, mcp-session-id",
        "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
      });
      res.end();
      return;
    }

    if (req.method !== "GET") {
      res.setHeader("access-control-allow-origin", "*");
      res.setHeader("access-control-expose-headers", "mcp-session-id");
    }

      // Extract bearer token and session ID from HTTP headers BEFORE processing
      const authHeader = req.headers.authorization;
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      
      // Debug logging
      console.log("=== MCP Request Debug ===");
      console.log("URL:", req.url);
      console.log("Method:", req.method);
      console.log("Session ID:", sessionId);
      console.log("Authorization header:", authHeader ? "Present" : "Missing");
      
      if (authHeader) {
        const token = parseBearerToken(authHeader);
        if (token) {
          pendingToken = token;
          if (sessionId) {
            console.log("Storing token for session:", sessionId, "token prefix:", token.substring(0, 20) + "...");
            sessionTokens.set(sessionId, token);
          }
        }
      } else if (sessionId && pendingToken) {
        console.log("Binding pending token to session:", sessionId, "token prefix:", pendingToken.substring(0, 20) + "...");
        sessionTokens.set(sessionId, pendingToken);
      }

      try {
        let parsedBody: unknown;
        if (req.method === "POST") {
          const chunks: Buffer[] = [];
          for await (const chunk of req) {
            chunks.push(chunk as Buffer);
          }
          const rawBody = Buffer.concat(chunks).toString("utf8");
          parsedBody = rawBody.length > 0 ? JSON.parse(rawBody) : undefined;
        }

        await transport.handleRequest(req, res, parsedBody);
    } catch (error) {
      console.error("HTTP request handling error:", error);

      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
      }

      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Internal server error",
          },
          id: null,
        }),
      );
    }
  });

  server.listen(port, () => {
    console.log(`MCP server is listening on http://localhost:${port}/mcp`);
  });
}

main().catch((error) => {
  console.error("Fatal error in MCP server:", error);
  process.exitCode = 1;
});
