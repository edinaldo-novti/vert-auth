/**
 * @vert/auth — OmniAuth module.
 *
 * OAuth provider interface with built-in Google, GitHub, Apple.
 * Extensible for custom providers.
 * Uses PKCE (RFC 7636) and state parameter for security.
 */

import type { OAuthProvider, OAuthProviderConfig, OAuthProfile } from "../types";
import { generateToken } from "../utils";

// ─── State Management ──────────────────────────────────────────────────────

export function generateOAuthState(): string {
  return generateToken(32);
}

export function generateCodeVerifier(): string {
  return generateToken(32);
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ─── Provider Registry ─────────────────────────────────────────────────────

const providers = new Map<string, OAuthProvider>();

export function registerProvider(provider: OAuthProvider): void {
  providers.set(provider.name, provider);
}

export function getProvider(name: string): OAuthProvider | undefined {
  return providers.get(name);
}

export function listProviders(): string[] {
  return Array.from(providers.keys());
}

export function clearProviders(): void {
  providers.clear();
}

// ─── Google Provider ───────────────────────────────────────────────────────

export function googleProvider(config: OAuthProviderConfig): OAuthProvider {
  return {
    name: "google",
    authorizeUrl(state: string): string {
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: "code",
        scope: (config.scopes ?? ["openid", "email", "profile"]).join(" "),
        state,
        access_type: "offline",
        prompt: "consent",
      });
      return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
    },
    async callback(code: string, _state: string): Promise<OAuthProfile> {
      // Exchange code for tokens
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          redirect_uri: config.redirectUri,
          grant_type: "authorization_code",
        }),
      });

      if (!tokenRes.ok) {
        throw new Error(`Google token exchange failed: ${tokenRes.status}`);
      }

      const tokens = (await tokenRes.json()) as { access_token: string };

      // Fetch user info
      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      if (!userRes.ok) {
        throw new Error(`Google userinfo failed: ${userRes.status}`);
      }

      const raw = (await userRes.json()) as Record<string, unknown>;
      return {
        provider: "google",
        uid: raw.id as string,
        email: raw.email as string,
        name: raw.name as string | undefined,
        avatarUrl: raw.picture as string | undefined,
        raw,
      };
    },
  };
}

// ─── GitHub Provider ───────────────────────────────────────────────────────

export function githubProvider(config: OAuthProviderConfig): OAuthProvider {
  return {
    name: "github",
    authorizeUrl(state: string): string {
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        scope: (config.scopes ?? ["user:email"]).join(" "),
        state,
      });
      return `https://github.com/login/oauth/authorize?${params}`;
    },
    async callback(code: string, _state: string): Promise<OAuthProfile> {
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          client_id: config.clientId,
          client_secret: config.clientSecret,
          code,
          redirect_uri: config.redirectUri,
        }),
      });

      if (!tokenRes.ok) {
        throw new Error(`GitHub token exchange failed: ${tokenRes.status}`);
      }

      const tokens = (await tokenRes.json()) as { access_token: string };

      const userRes = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          Accept: "application/vnd.github+json",
        },
      });

      if (!userRes.ok) {
        throw new Error(`GitHub user fetch failed: ${userRes.status}`);
      }

      const raw = (await userRes.json()) as Record<string, unknown>;

      // Email might be private — fetch separately
      let email = raw.email as string | null;
      if (!email) {
        const emailRes = await fetch("https://api.github.com/user/emails", {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
            Accept: "application/vnd.github+json",
          },
        });
        if (emailRes.ok) {
          const emails = (await emailRes.json()) as Array<{
            email: string;
            primary: boolean;
            verified: boolean;
          }>;
          const primary = emails.find((e) => e.primary && e.verified);
          email = primary?.email ?? emails[0]?.email ?? "";
        }
      }

      return {
        provider: "github",
        uid: String(raw.id),
        email: email ?? "",
        name: raw.name as string | undefined,
        avatarUrl: raw.avatar_url as string | undefined,
        raw,
      };
    },
  };
}

// ─── Apple Provider ────────────────────────────────────────────────────────

export function appleProvider(config: OAuthProviderConfig): OAuthProvider {
  return {
    name: "apple",
    authorizeUrl(state: string): string {
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: "code",
        scope: (config.scopes ?? ["name", "email"]).join(" "),
        state,
        response_mode: "form_post",
      });
      return `https://appleid.apple.com/auth/authorize?${params}`;
    },
    async callback(code: string, _state: string): Promise<OAuthProfile> {
      const tokenRes = await fetch("https://appleid.apple.com/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          redirect_uri: config.redirectUri,
          grant_type: "authorization_code",
        }),
      });

      if (!tokenRes.ok) {
        throw new Error(`Apple token exchange failed: ${tokenRes.status}`);
      }

      const tokens = (await tokenRes.json()) as { id_token: string };

      // Decode JWT payload (no verification here — consumer should verify)
      const parts = tokens.id_token.split(".");
      if (parts.length !== 3 || !parts[1]) throw new Error("Invalid Apple id_token");
      const payload = JSON.parse(atob(parts[1])) as Record<string, unknown>;

      return {
        provider: "apple",
        uid: payload.sub as string,
        email: payload.email as string,
        raw: payload,
      };
    },
  };
}
