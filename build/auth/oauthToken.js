import { storeUserToken } from "./oauthServer.js";
import { randomUUID } from "node:crypto";
export async function handleOAuthToken(req, res, body) {
    const params = new URLSearchParams(body);
    const grantType = params.get("grant_type");
    const code = params.get("code");
    if (grantType !== "authorization_code" || !code) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_request" }));
        return;
    }
    // In our implementation, the code IS the music user token
    // Generate a session-specific access token
    const accessToken = randomUUID();
    const sessionId = accessToken; // Use access token as session ID
    // Store the actual music user token linked to this session
    storeUserToken(sessionId, code, 3600 * 24 * 90); // 90 days
    const response = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600 * 24 * 90, // 90 days
        scope: "music.library.read music.library.write",
    };
    res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
    });
    res.end(JSON.stringify(response));
}
