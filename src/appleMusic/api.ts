import { createDeveloperTokenProvider, getMusicUserToken } from "../auth/appleMusicAuth.js";

export type AppleMusicAPIOptions = {
  storefrontDefault?: string;
  getDeveloperToken?: () => Promise<string>;
  getUserToken?: () => string | undefined;
  // Deprecated in stateless mode
  getSessionToken?: (sessionId?: string) => string | undefined;
};

export class AppleMusicAPI {
  private readonly baseUrl = "https://api.music.apple.com";
  private readonly storefrontDefault: string;
  private readonly getDeveloperToken: () => Promise<string>;
  private readonly getUserToken: () => string | undefined;
  private readonly getSessionToken?: (sessionId?: string) => string | undefined;

  constructor(options?: AppleMusicAPIOptions) {
    this.storefrontDefault = options?.storefrontDefault ?? process.env.APPLE_MUSIC_STOREFRONT ?? "us";
    this.getDeveloperToken = options?.getDeveloperToken ?? createDeveloperTokenProvider();
    this.getUserToken = options?.getUserToken ?? getMusicUserToken;
    this.getSessionToken = options?.getSessionToken;
  }

  private async request<T>(
    path: string,
    init: any = {},
    requiresUserToken = false,
    userTokenOverride?: string,
  ): Promise<T> {
    const devToken = await this.getDeveloperToken();
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    headers["Authorization"] = `Bearer ${devToken}`;
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";

    if (requiresUserToken) {
      // Prefer explicit override, then in-memory token
      const userToken = userTokenOverride || this.getUserToken();
      if (!userToken) {
        throw new Error("This operation requires a Music User Token. Authenticate via OAuth or set it with the auth tool.");
      }
      headers["Music-User-Token"] = userToken;
    }

    const url = `${this.baseUrl}${path}`;
    const res = await fetch(url, { ...init, headers });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Apple Music API error ${res.status}: ${text || res.statusText}`);
    }

    // Some endpoints may return empty responses
    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return (await res.text()) as unknown as T;
    }
    return (await res.json()) as T;
  }

  // Catalog
  async searchCatalog(params: { term: string; types?: string; storefront?: string; limit?: number }) {
    const storefront = params.storefront ?? this.storefrontDefault;
    const sp = new URLSearchParams();
    sp.set("term", params.term);
    if (params.types) sp.set("types", params.types);
    if (params.limit) sp.set("limit", String(params.limit));
    return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/search?${sp.toString()}`);
  }

  async getSong(params: { id: string; storefront?: string }) {
    const storefront = params.storefront ?? this.storefrontDefault;
    return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/songs/${encodeURIComponent(params.id)}`);
  }

  async getSongsByIsrc(params: { isrc: string; storefront?: string }) {
    const storefront = params.storefront ?? this.storefrontDefault;
    const sp = new URLSearchParams();
    sp.set("filter[isrc]", params.isrc);
    return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/songs?${sp.toString()}`);
  }

  // Library (requires user token)
  async listLibrarySongs(params?: { limit?: number; offset?: string }, userToken?: string) {
    const sp = new URLSearchParams();
    if (params?.limit) sp.set("limit", String(params.limit));
    if (params?.offset) sp.set("offset", params.offset);
    return this.request(`/v1/me/library/songs${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
  }

  async searchLibrary(params: { term: string; types?: string; limit?: number }, userToken?: string) {
    const sp = new URLSearchParams();
    sp.set("term", params.term);
    if (params.types) sp.set("types", params.types);
    if (params.limit) sp.set("limit", String(params.limit));
    return this.request(`/v1/me/library/search?${sp.toString()}`, { method: "GET" }, true, userToken);
  }

  async listLibraryPlaylists(params?: { limit?: number; offset?: string }, userToken?: string) {
    const sp = new URLSearchParams();
    if (params?.limit) sp.set("limit", String(params.limit));
    if (params?.offset) sp.set("offset", params.offset);
    return this.request(`/v1/me/library/playlists${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
  }

  async getPlaylistTracks(params: { id: string; limit?: number; offset?: string }, userToken?: string) {
    const sp = new URLSearchParams();
    if (params.limit) sp.set("limit", String(params.limit));
    if (params.offset) sp.set("offset", params.offset);
    return this.request(
      `/v1/me/library/playlists/${encodeURIComponent(params.id)}/tracks${sp.size ? `?${sp.toString()}` : ""}`,
      { method: "GET" },
      true,
      userToken,
    );
  }

  async addToLibrary(params: { songIds?: string[]; albumIds?: string[] }, userToken?: string) {
    const sp = new URLSearchParams();
    if (params.songIds?.length) sp.set("ids[songs]", params.songIds.join(","));
    if (params.albumIds?.length) sp.set("ids[albums]", params.albumIds.join(","));
    return this.request(`/v1/me/library?${sp.toString()}`, { method: "POST" }, true, userToken);
  }

  async createPlaylist(params: { name: string; description?: string; trackIds?: string[] }, userToken?: string) {
    const body: any = { attributes: { name: params.name } };
    if (params.description) body.attributes.description = params.description;
    if (params.trackIds?.length) {
      body.relationships = {
        tracks: {
          data: params.trackIds.map((id) => ({ id, type: inferItemTypeFromId(id) })),
        },
      };
    }
    return this.request(`/v1/me/library/playlists`, { method: "POST", body: JSON.stringify(body) }, true, userToken);
  }

  async addTracksToPlaylist(params: { playlistId: string; trackIds: string[] }, userToken?: string) {
    const body = {
      data: params.trackIds.map((id) => ({ id, type: inferItemTypeFromId(id) })),
    };
    return this.request(
      `/v1/me/library/playlists/${encodeURIComponent(params.playlistId)}/tracks`,
      { method: "POST", body: JSON.stringify(body) },
      true,
      userToken,
    );
  }

  async getReplay(params?: { year?: number }, userToken?: string) {
    const sp = new URLSearchParams();
    if (params?.year) sp.set("year", String(params.year));
    return this.request(`/v1/me/replay${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
  }
}

function inferItemTypeFromId(id: string): string {
  // Heuristic: Apple Music identifiers are not self-describing; default to 'songs'
  // Allow overriding via more specific tools if needed.
  return "songs";
}


