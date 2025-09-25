import { SignJWT, importPKCS8, decodeJwt, JWTPayload } from "jose";

export type AppleMusicAuthConfig = {
  teamId: string;
  keyId: string;
  privateKey: string; // PKCS8 PEM
  tokenTTLSeconds?: number; // max ~6 months, we'll clamp
};

const SIX_MONTHS_SECONDS = 60 * 60 * 24 * 30 * 6;

type CachedToken = {
  token: string;
  expiresAtEpoch: number; // seconds
};

function clampTTL(ttlSeconds: number): number {
  const safe = Math.max(60, Math.min(ttlSeconds, SIX_MONTHS_SECONDS));
  return safe;
}

export async function generateDeveloperToken(config: AppleMusicAuthConfig): Promise<string> {
  const { teamId, keyId, privateKey } = config;
  const ttl = clampTTL(config.tokenTTLSeconds ?? 60 * 60 * 24); // default 1 day

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const pkcs8 = await importPKCS8(privateKey, "ES256");
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: keyId })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer(teamId)
    .sign(pkcs8);

  return token;
}

export function getDeveloperConfigFromEnv(): AppleMusicAuthConfig {
  const teamId = process.env.APPLE_MUSIC_TEAM_ID;
  const keyId = process.env.APPLE_MUSIC_KEY_ID;
  const privateKey = process.env.APPLE_MUSIC_PRIVATE_KEY;
  const tokenTTLSeconds = process.env.APPLE_MUSIC_DEV_TOKEN_TTL_SECONDS
    ? Number.parseInt(process.env.APPLE_MUSIC_DEV_TOKEN_TTL_SECONDS, 10)
    : undefined;

  if (!teamId || !keyId || !privateKey) {
    throw new Error(
      "Missing Apple Music credentials. Set APPLE_MUSIC_TEAM_ID, APPLE_MUSIC_KEY_ID, APPLE_MUSIC_PRIVATE_KEY in env.",
    );
  }

  return { teamId, keyId, privateKey, tokenTTLSeconds };
}

export function createDeveloperTokenProvider(initialConfig?: AppleMusicAuthConfig) {
  let cached: CachedToken | undefined;
  let inFlight: Promise<string> | undefined;

  async function getToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (cached && cached.expiresAtEpoch - 300 > now) {
      return cached.token;
    }
    if (inFlight) return inFlight;

    inFlight = (async () => {
      const config = initialConfig ?? getDeveloperConfigFromEnv();
      const token = await generateDeveloperToken(config);
      const decoded = decodeJwt(token) as JWTPayload;
      const exp = typeof decoded.exp === "number" ? decoded.exp : now + clampTTL(config.tokenTTLSeconds ?? 3600);
      cached = { token, expiresAtEpoch: exp };
      inFlight = undefined;
      return token;
    })();

    try {
      return await inFlight;
    } finally {
      inFlight = undefined;
    }
  }

  return getToken;
}

let musicUserToken: string | undefined;

export function setMusicUserToken(token: string): void {
  musicUserToken = token.trim();
}

export function getMusicUserToken(): string | undefined {
  return musicUserToken;
}

export function requireMusicUserToken(): string {
  if (!musicUserToken) {
    throw new Error("Missing Music User Token. Use the auth tool to set it.");
  }
  return musicUserToken;
}


