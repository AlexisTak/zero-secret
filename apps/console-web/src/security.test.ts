// Tests de sécurité console-web — même patron que server.test.ts (vrai serveur HTTP, pas de faux
// backend nécessaire pour CSRF/session : ces contrôles s'exécutent AVANT tout appel aux clients
// identity-provider/access-broker/admin-api).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createApp, type ServerConfig } from "./server.js";
import { HttpIdentityProviderClient } from "./clients/identity-provider.js";
import { HttpAccessBrokerClient } from "./clients/access-broker.js";
import { HttpAdminApiClient } from "./clients/admin-api.js";

async function listenEphemeral(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

function minimalConfig(origin: string): ServerConfig {
  // Aucun backend n'est censé être appelé par les tests de ce fichier — CSRF et session-gating se
  // décident avant tout appel réseau sortant (server.ts:42, server.ts:234-240).
  const deadUrl = "http://127.0.0.1:1"; // port jamais écouté — un appel ici ferait échouer le test bruyamment
  return {
    origin,
    identityProvider: new HttpIdentityProviderClient(deadUrl),
    accessBroker: new HttpAccessBrokerClient(deadUrl),
    adminApi: new HttpAdminApiClient(deadUrl),
    expectedAuthorityDomain: "corp.eu-west",
    sessionTtlSeconds: 900,
    publicDir: ".",
  };
}

test("TestSecurityCSRF: POST sans Origin ni Sec-Fetch-Site same-origin est refusé 403", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "resource_type=Database&resource_id=x",
  });

  assert.equal(resp.status, 403, "un POST cross-origin (aucun Origin/Sec-Fetch-Site attendu) doit être refusé");
  app.close();
});

test("TestSecurityCSRF: POST avec Origin falsifié différent de config.origin est refusé 403", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      origin: "https://attaquant.example",
    },
    body: "resource_type=Database&resource_id=x",
  });

  assert.equal(resp.status, 403, "un Origin différent de config.origin doit être refusé");
  app.close();
});

test("TestSecuritySession: /access-request sans cookie de session redirige vers /login, ne fuit rien", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "GET",
    redirect: "manual",
  });

  assert.equal(resp.status, 302, "sans cookie de session, /access-request doit rediriger, jamais servir la page");
  assert.equal(resp.headers.get("location"), "/login");
  app.close();
});

test("TestSecuritySession: /quorum sans cookie de session redirige vers /login", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/quorum`, {
    method: "GET",
    redirect: "manual",
  });

  assert.equal(resp.status, 302, "sans cookie de session, /quorum doit rediriger, jamais servir la page");
  assert.equal(resp.headers.get("location"), "/login");
  app.close();
});

test("TestSecuritySession: cookie de session forgé (mauvaise longueur) est refusé comme absent", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "GET",
    redirect: "manual",
    headers: { cookie: "__Host-session=cookie-invente-par-un-attaquant" },
  });

  assert.equal(resp.status, 302, "un identifiant de session non enregistré doit être traité comme absent");
  app.close();
});
