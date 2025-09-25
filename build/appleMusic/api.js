import { createDeveloperTokenProvider } from "../auth/appleMusicAuth.js";
export class AppleMusicAPI {
    baseUrl = "https://api.music.apple.com";
    storefrontDefault;
    getDeveloperToken;
    getUserToken;
    constructor(options) {
        this.storefrontDefault = options?.storefrontDefault ?? process.env.APPLE_MUSIC_STOREFRONT ?? "us";
        this.getDeveloperToken = options?.getDeveloperToken ?? createDeveloperTokenProvider();
        this.getUserToken = options?.getUserToken ?? (() => undefined);
    }
    async request(path, init = {}, requiresUserToken = false, userTokenOverride) {
        const devToken = await this.getDeveloperToken();
        const headers = { ...(init.headers ?? {}) };
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
            return (await res.text());
        }
        return (await res.json());
    }
    // Catalog
    async searchCatalog(params) {
        const storefront = params.storefront ?? this.storefrontDefault;
        const sp = new URLSearchParams();
        sp.set("term", params.term);
        if (params.types)
            sp.set("types", params.types);
        if (params.limit)
            sp.set("limit", String(params.limit));
        return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/search?${sp.toString()}`);
    }
    async getSong(params) {
        const storefront = params.storefront ?? this.storefrontDefault;
        return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/songs/${encodeURIComponent(params.id)}`);
    }
    async getSongsByIsrc(params) {
        const storefront = params.storefront ?? this.storefrontDefault;
        const sp = new URLSearchParams();
        sp.set("filter[isrc]", params.isrc);
        return this.request(`/v1/catalog/${encodeURIComponent(storefront)}/songs?${sp.toString()}`);
    }
    // Library (requires user token)
    async listLibrarySongs(params, userToken) {
        const sp = new URLSearchParams();
        if (params?.limit)
            sp.set("limit", String(params.limit));
        if (params?.offset)
            sp.set("offset", params.offset);
        return this.request(`/v1/me/library/songs${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
    }
    async searchLibrary(params, userToken) {
        const sp = new URLSearchParams();
        sp.set("term", params.term);
        if (params.types)
            sp.set("types", params.types);
        if (params.limit)
            sp.set("limit", String(params.limit));
        return this.request(`/v1/me/library/search?${sp.toString()}`, { method: "GET" }, true, userToken);
    }
    async listLibraryPlaylists(params, userToken) {
        const sp = new URLSearchParams();
        if (params?.limit)
            sp.set("limit", String(params.limit));
        if (params?.offset)
            sp.set("offset", params.offset);
        return this.request(`/v1/me/library/playlists${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
    }
    async getPlaylistTracks(params, userToken) {
        const sp = new URLSearchParams();
        if (params.limit)
            sp.set("limit", String(params.limit));
        if (params.offset)
            sp.set("offset", params.offset);
        return this.request(`/v1/me/library/playlists/${encodeURIComponent(params.id)}/tracks${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
    }
    async addToLibrary(params, userToken) {
        const sp = new URLSearchParams();
        if (params.songIds?.length)
            sp.set("ids[songs]", params.songIds.join(","));
        if (params.albumIds?.length)
            sp.set("ids[albums]", params.albumIds.join(","));
        return this.request(`/v1/me/library?${sp.toString()}`, { method: "POST" }, true, userToken);
    }
    async createPlaylist(params, userToken) {
        const body = { attributes: { name: params.name } };
        if (params.description)
            body.attributes.description = params.description;
        if (params.trackIds?.length) {
            body.relationships = {
                tracks: {
                    data: params.trackIds.map((id) => ({ id, type: inferItemTypeFromId(id) })),
                },
            };
        }
        return this.request(`/v1/me/library/playlists`, { method: "POST", body: JSON.stringify(body) }, true, userToken);
    }
    async addTracksToPlaylist(params, userToken) {
        const body = {
            data: params.trackIds.map((id) => ({ id, type: inferItemTypeFromId(id) })),
        };
        return this.request(`/v1/me/library/playlists/${encodeURIComponent(params.playlistId)}/tracks`, { method: "POST", body: JSON.stringify(body) }, true, userToken);
    }
    async getReplay(params, userToken) {
        const sp = new URLSearchParams();
        if (params?.year)
            sp.set("year", String(params.year));
        return this.request(`/v1/me/replay${sp.size ? `?${sp.toString()}` : ""}`, { method: "GET" }, true, userToken);
    }
}
function inferItemTypeFromId(id) {
    // Heuristic: Apple Music identifiers are not self-describing; default to 'songs'
    // Allow overriding via more specific tools if needed.
    return "songs";
}
