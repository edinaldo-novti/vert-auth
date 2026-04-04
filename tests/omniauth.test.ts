/**
 * @vert/auth — OmniAuth module tests.
 */

import { describe, test, expect, afterEach } from "bun:test";
import {
  registerProvider,
  getProvider,
  listProviders,
  clearProviders,
  generateOAuthState,
  generateCodeVerifier,
  generateCodeChallenge,
  googleProvider,
  githubProvider,
  appleProvider,
} from "../src/omniauth";

afterEach(() => {
  clearProviders();
});

describe("OmniAuth", () => {
  describe("provider registry", () => {
    test("registers and retrieves a provider", () => {
      const provider = googleProvider({
        clientId: "test-client-id",
        clientSecret: "test-secret-do-not-use-in-production",
        redirectUri: "http://localhost:3000/callback",
      });
      registerProvider(provider);
      expect(getProvider("google")).toBe(provider);
    });

    test("returns undefined for unregistered provider", () => {
      expect(getProvider("unknown")).toBeUndefined();
    });

    test("lists registered providers", () => {
      registerProvider(googleProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      }));
      registerProvider(githubProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      }));
      const names = listProviders();
      expect(names).toContain("google");
      expect(names).toContain("github");
      expect(names.length).toBe(2);
    });

    test("clearProviders empties registry", () => {
      registerProvider(googleProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      }));
      clearProviders();
      expect(listProviders().length).toBe(0);
    });
  });

  describe("PKCE", () => {
    test("generateOAuthState returns 64 char hex", () => {
      const state = generateOAuthState();
      expect(state.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(state)).toBe(true);
    });

    test("generateCodeVerifier returns 64 char hex", () => {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBe(64);
    });

    test("generateCodeChallenge is base64url of SHA-256", async () => {
      const verifier = "test-verifier";
      const challenge = await generateCodeChallenge(verifier);
      expect(challenge).toBeTruthy();
      // base64url: no +, /, or = characters
      expect(challenge).not.toContain("+");
      expect(challenge).not.toContain("/");
      expect(challenge).not.toContain("=");
    });

    test("same verifier always produces same challenge", async () => {
      const verifier = "deterministic-verifier";
      const c1 = await generateCodeChallenge(verifier);
      const c2 = await generateCodeChallenge(verifier);
      expect(c1).toBe(c2);
    });
  });

  describe("Google provider", () => {
    test("generates valid authorize URL", () => {
      const provider = googleProvider({
        clientId: "test-client-id",
        clientSecret: "test-secret-do-not-use-in-production",
        redirectUri: "http://localhost:3000/callback",
      });

      const url = provider.authorizeUrl("test-state");
      expect(url).toContain("accounts.google.com");
      expect(url).toContain("client_id=test-client-id");
      expect(url).toContain("state=test-state");
      expect(url).toContain("response_type=code");
      expect(url).toContain("redirect_uri=");
    });

    test("name is google", () => {
      const provider = googleProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      });
      expect(provider.name).toBe("google");
    });
  });

  describe("GitHub provider", () => {
    test("generates valid authorize URL", () => {
      const provider = githubProvider({
        clientId: "test-client-id",
        clientSecret: "test-secret-do-not-use-in-production",
        redirectUri: "http://localhost:3000/callback",
      });

      const url = provider.authorizeUrl("test-state");
      expect(url).toContain("github.com/login/oauth/authorize");
      expect(url).toContain("client_id=test-client-id");
      expect(url).toContain("state=test-state");
    });

    test("name is github", () => {
      const provider = githubProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      });
      expect(provider.name).toBe("github");
    });
  });

  describe("Apple provider", () => {
    test("generates valid authorize URL with form_post mode", () => {
      const provider = appleProvider({
        clientId: "test-client-id",
        clientSecret: "test-secret-do-not-use-in-production",
        redirectUri: "http://localhost:3000/callback",
      });

      const url = provider.authorizeUrl("test-state");
      expect(url).toContain("appleid.apple.com/auth/authorize");
      expect(url).toContain("response_mode=form_post");
      expect(url).toContain("state=test-state");
    });

    test("name is apple", () => {
      const provider = appleProvider({
        clientId: "id", clientSecret: "test-secret-do-not-use-in-production", redirectUri: "http://localhost/cb",
      });
      expect(provider.name).toBe("apple");
    });
  });
});
