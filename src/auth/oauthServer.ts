import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createDeveloperTokenProvider } from "./appleMusicAuth.js";

// In-memory store for OAuth states and tokens
const pendingStates = new Map<string, { redirectUri: string; expiresAt: number }>();
const userTokens = new Map<string, { token: string; expiresAt?: number }>();

// Clean up expired states periodically
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of pendingStates) {
    if (data.expiresAt < now) {
      pendingStates.delete(state);
    }
  }
}, 60000); // every minute

export function getStoredUserToken(sessionId?: string): string | undefined {
  if (!sessionId) return undefined;
  const stored = userTokens.get(sessionId);
  if (!stored) return undefined;
  if (stored.expiresAt && stored.expiresAt < Date.now()) {
    userTokens.delete(sessionId);
    return undefined;
  }
  return stored.token;
}

export function storeUserToken(sessionId: string, token: string, expiresIn?: number): void {
  const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : undefined;
  userTokens.set(sessionId, { token, expiresAt });
}

export async function handleOAuthAuthorize(
  req: IncomingMessage,
  res: ServerResponse,
  searchParams: URLSearchParams,
): Promise<void> {
  const redirectUri = searchParams.get("redirect_uri");
  const state = searchParams.get("state");
  
  if (!redirectUri || !state) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Missing redirect_uri or state");
    return;
  }

  // Store state for verification
  pendingStates.set(state, { redirectUri, expiresAt: Date.now() + 600000 }); // 10 min

  // Get developer token for MusicKit JS
  const getDevToken = createDeveloperTokenProvider();
  const developerToken = await getDevToken();

  // Serve HTML page with MusicKit JS
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Apple Music Authorization</title>
  <script src="https://js-cdn.music.apple.com/musickit/v3/musickit.js"></script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f7;
    }
    .container {
      text-align: center;
      background: white;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      max-width: 400px;
    }
    h1 { font-size: 24px; margin-bottom: 20px; }
    p { color: #666; margin-bottom: 30px; }
    button {
      background: #fc3c44;
      color: white;
      border: none;
      padding: 12px 24px;
      font-size: 16px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 500;
    }
    button:hover { background: #e5353c; }
    button:disabled {
      background: #ccc;
      cursor: not-allowed;
    }
    .error { color: #d60017; margin-top: 20px; }
    .success { color: #28a745; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Connect Apple Music</h1>
    <p>Click below to authorize access to your Apple Music library.</p>
    <button id="authBtn" onclick="authorize()">Authorize Apple Music</button>
    <div id="status"></div>
  </div>

  <script>
    let music;
    const state = ${JSON.stringify(state)};
    
    async function initialize() {
      try {
        await MusicKit.configure({
          developerToken: ${JSON.stringify(developerToken)},
          app: {
            name: 'Apple Music MCP',
            build: '1.0.0'
          }
        });
        music = MusicKit.getInstance();
      } catch (error) {
        showError('Failed to initialize MusicKit: ' + error.message);
      }
    }

    async function authorize() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      
      btn.disabled = true;
      status.innerHTML = '<p>Authorizing...</p>';
      
      try {
        const musicUserToken = await music.authorize();
        status.innerHTML = '<p class="success">Authorization successful! Redirecting...</p>';
        
        // Send token to callback endpoint
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/oauth/callback';
        
        const tokenInput = document.createElement('input');
        tokenInput.type = 'hidden';
        tokenInput.name = 'music_user_token';
        tokenInput.value = musicUserToken;
        
        const stateInput = document.createElement('input');
        stateInput.type = 'hidden';
        stateInput.name = 'state';
        stateInput.value = state;
        
        form.appendChild(tokenInput);
        form.appendChild(stateInput);
        document.body.appendChild(form);
        form.submit();
      } catch (error) {
        btn.disabled = false;
        showError('Authorization failed: ' + (error.message || 'User cancelled'));
      }
    }

    function showError(message) {
      document.getElementById('status').innerHTML = '<p class="error">' + message + '</p>';
    }

    // Initialize on load
    initialize();
  </script>
</body>
</html>`;

  res.writeHead(200, { "content-type": "text/html" });
  res.end(html);
}

export async function handleOAuthCallback(
  req: IncomingMessage,
  res: ServerResponse,
  body: string,
): Promise<void> {
  // Parse form data
  const params = new URLSearchParams(body);
  const musicUserToken = params.get("music_user_token");
  const state = params.get("state");

  if (!musicUserToken || !state) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Missing token or state");
    return;
  }

  // Verify state
  const stateData = pendingStates.get(state);
  if (!stateData) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Invalid or expired state");
    return;
  }

  pendingStates.delete(state);

  // Generate access token (we'll use the music user token directly)
  const accessToken = musicUserToken;
  
  // Store with session
  const sessionId = randomUUID();
  storeUserToken(sessionId, musicUserToken);

  // Redirect back with token
  const redirectUrl = new URL(stateData.redirectUri);
  redirectUrl.searchParams.set("code", accessToken);
  redirectUrl.searchParams.set("state", state);

  res.writeHead(302, { Location: redirectUrl.toString() });
  res.end();
}

export function getOAuthMetadata(baseUrl: string) {
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    response_types_supported: ["code"],
    response_modes_supported: ["query", "fragment"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["plain", "S256"],
    scopes_supported: ["music.library.read", "music.library.write"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["sub", "aud", "exp", "iat", "iss"],
  };
}
