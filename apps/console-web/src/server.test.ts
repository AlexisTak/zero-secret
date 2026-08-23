// Tests d'intégration réels : un vrai serveur HTTP console-web, appelé par de vraies requêtes
// HTTP, contre de faux serveurs identity-provider/access-broker en process. Légitime de mocker
// ces dépendances HTTP directes : console-web ne fait elle-même aucune vérification
// cryptographique (ADR-024), contrairement à un HSM qu'on ne mockerait jamais (voir
// crates/zs-hsm/tests/pkcs11_integration.rs pour ce contre-exemple).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createApp } from "./server.js";
import { HttpIdentityProviderClient } from "./clients/identity-provider.js";
import { HttpAccessBrokerClient } from "./clients/access-broker.js";
import { HttpAdminApiClient } from "./clients/admin-api.js";

async function listenEphemeral(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

function fakeIdentityProvider(): Server {
  return createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf-8") || "{}");
    res.setHeader("content-type", "application/json");

    if (req.url === "/v1/webauthn/authentication/challenge") {
      res.end(
        JSON.stringify({
          challenge: "Y2hhbGxlbmdl",
          rp_id: "zero-secret.example",
          expires_at: "2026-08-23T10:02:00Z",
          allow_credentials: ["Y3JlZA"],
        }),
      );
      return;
    }
    if (req.url === "/v1/webauthn/authentication/verify") {
      res.end(JSON.stringify({ assertion: "YXNzZXJ0aW9uLWZha2U" }));
      return;
    }
    if (req.url === "/v1/webauthn/registration/challenge") {
      res.end(
        JSON.stringify({
          challenge: "Y2hhbGxlbmdl",
          rp_id: "zero-secret.example",
          expires_at: "2026-08-23T10:02:00Z",
        }),
      );
      return;
    }
    if (req.url === "/v1/webauthn/registration/verify") {
      res.end(JSON.stringify({ credential_id: "Y3JlZA" }));
      return;
    }
    void body;
    res.statusCode = 404;
    res.end(JSON.stringify({ reason: "introuvable" }));
  });
}

function fakeAccessBroker(behavior: "allow" | "deny" | "unauthorized"): Server {
  return createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (behavior === "unauthorized") {
      res.statusCode = 401;
      res.end(JSON.stringify({ reason: "assertion_invalide" }));
      return;
    }
    res.end(
      JSON.stringify(
        behavior === "allow"
          ? { allowed: true, reasons: ["db-connect-production"] }
          : { allowed: false, reasons: ["politique_refusee"] },
      ),
    );
  });
}

function fakeAdminApi(behavior: "reached" | "not-reached" | "threshold-too-low"): Server {
  return createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (behavior === "threshold-too-low") {
      res.statusCode = 400;
      res.end(JSON.stringify({ reason: "seuil_de_quorum_invalide" }));
      return;
    }
    res.end(
      JSON.stringify(
        behavior === "reached"
          ? { reached: true, distinct_subjects: ["subject-1", "subject-2"] }
          : { reached: false, distinct_subjects: ["subject-1"] },
      ),
    );
  });
}

async function request(
  baseUrl: string,
  method: string,
  pathname: string,
  init: { body?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: Headers; text: string }> {
  const response = await fetch(new URL(pathname, baseUrl), {
    method,
    redirect: "manual",
    headers: {
      origin: baseUrl,
      "sec-fetch-site": "same-origin",
      ...init.headers,
    },
    ...(init.body !== undefined ? { body: init.body } : {}),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, text };
}

async function withServers(
  accessBrokerBehavior: "allow" | "deny" | "unauthorized",
  fn: (consoleWebUrl: string) => Promise<void>,
  adminApiBehavior: "reached" | "not-reached" | "threshold-too-low" = "reached",
): Promise<void> {
  const idp = fakeIdentityProvider();
  const ab = fakeAccessBroker(accessBrokerBehavior);
  const admin = fakeAdminApi(adminApiBehavior);
  const idpUrl = await listenEphemeral(idp);
  const abUrl = await listenEphemeral(ab);
  const adminUrl = await listenEphemeral(admin);

  const consoleWeb = createApp({
    origin: "http://console-web.test",
    identityProvider: new HttpIdentityProviderClient(idpUrl),
    accessBroker: new HttpAccessBrokerClient(abUrl),
    adminApi: new HttpAdminApiClient(adminUrl),
    expectedAuthorityDomain: "access-broker",
    sessionTtlSeconds: 60,
    publicDir: new URL("../public", import.meta.url).pathname,
  });
  const consoleWebUrl = await listenEphemeral(consoleWeb);

  try {
    await fn(consoleWebUrl);
  } finally {
    idp.close();
    ab.close();
    admin.close();
    consoleWeb.close();
  }
}

async function loginAndGetCookie(base: string): Promise<string> {
  const verify = await request(base, "POST", "/api/webauthn/authentication/verify", {
    body: JSON.stringify({
      subject_id: "subject-1",
      credential_id: "Y3JlZA",
      client_data_json: "Y2xpZW50",
      authenticator_data: "YXV0aA",
      signature: "c2ln",
    }),
    headers: { "content-type": "application/json" },
  });
  return verify.headers.get("set-cookie")!.split(";")[0]!;
}

test("GET /register rend une page HTML avec le formulaire", async () => {
  await withServers("allow", async (base) => {
    const res = await request(base, "GET", "/register", {
      headers: { "sec-fetch-site": "none" },
    });
    assert.equal(res.status, 200);
    assert.match(res.text, /register-form/);
  });
});

test("GET /access-request sans session redirige vers /login", async () => {
  await withServers("allow", async (base) => {
    const res = await request(base, "GET", "/access-request", {
      headers: { "sec-fetch-site": "none" },
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/login");
  });
});

test("POST sans origine correspondante est refusé (CSRF)", async () => {
  await withServers("allow", async (base) => {
    const res = await request(base, "POST", "/logout", {
      headers: { origin: "http://attacker.example", "sec-fetch-site": "cross-site" },
    });
    assert.equal(res.status, 403);
  });
});

test("parcours complet : authentification puis demande d'accès autorisée", async () => {
  await withServers("allow", async (base) => {
    const verify = await request(base, "POST", "/api/webauthn/authentication/verify", {
      body: JSON.stringify({
        subject_id: "subject-1",
        credential_id: "Y3JlZA",
        client_data_json: "Y2xpZW50",
        authenticator_data: "YXV0aA",
        signature: "c2ln",
      }),
      headers: { "content-type": "application/json" },
    });
    assert.equal(verify.status, 200);
    const setCookie = verify.headers.get("set-cookie");
    assert.ok(setCookie?.startsWith("__Host-session="));
    const cookie = setCookie!.split(";")[0]!;

    const accessPage = await request(base, "GET", "/access-request", {
      headers: { cookie, "sec-fetch-site": "none" },
    });
    assert.equal(accessPage.status, 200);
    assert.match(accessPage.text, /subject-1/);

    const form = new URLSearchParams({
      verb: "db.connect",
      resource_type: "Database",
      resource_id: "db-1",
      resource_authority_domain: "corp.eu-west",
      justification: "correctif urgent",
      ticket_ref: "INC-1",
    });
    const submit = await request(base, "POST", "/access-request", {
      body: form.toString(),
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(submit.status, 200);
    assert.match(submit.text, /Accès autorisé/);
    assert.match(submit.text, /db-connect-production/);
  });
});

test("401 d'access-broker détruit la session et efface le cookie", async () => {
  await withServers("unauthorized", async (base) => {
    const verify = await request(base, "POST", "/api/webauthn/authentication/verify", {
      body: JSON.stringify({
        subject_id: "subject-1",
        credential_id: "Y3JlZA",
        client_data_json: "Y2xpZW50",
        authenticator_data: "YXV0aA",
        signature: "c2ln",
      }),
      headers: { "content-type": "application/json" },
    });
    const cookie = verify.headers.get("set-cookie")!.split(";")[0]!;

    const form = new URLSearchParams({
      verb: "db.connect",
      resource_type: "Database",
      resource_id: "db-1",
      resource_authority_domain: "corp.eu-west",
      justification: "x",
      ticket_ref: "INC-1",
    });
    const submit = await request(base, "POST", "/access-request", {
      body: form.toString(),
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(submit.status, 302);
    assert.equal(submit.headers.get("location"), "/login");
    assert.match(submit.headers.get("set-cookie") ?? "", /Max-Age=0/);

    // La session doit être réellement détruite côté serveur — un accès ultérieur avec le même
    // cookie doit à nouveau rediriger vers /login, pas rester valide.
    const again = await request(base, "GET", "/access-request", {
      headers: { cookie, "sec-fetch-site": "none" },
    });
    assert.equal(again.status, 302);
  });
});

// --- L2.6b : écran quorum -----------------------------------------------------------------

test("GET /quorum sans session redirige vers /login", async () => {
  await withServers("allow", async (base) => {
    const res = await request(base, "GET", "/quorum", {
      headers: { "sec-fetch-site": "none" },
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/login");
  });
});

test("POST /quorum nominal affiche le résultat du quorum", async () => {
  await withServers(
    "allow",
    async (base) => {
      const cookie = await loginAndGetCookie(base);

      const form = new URLSearchParams({
        operation_id: "op-1",
        threshold: "2",
        expected_authority_domain: "admin-api",
        assertions: "AQID\nBAUG", // deux lignes base64 standard valides
      });
      const submit = await request(base, "POST", "/quorum", {
        body: form.toString(),
        headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      });
      assert.equal(submit.status, 200);
      assert.match(submit.text, /Quorum atteint/);
      assert.match(submit.text, /subject-1/);
      assert.match(submit.text, /subject-2/);
    },
    "reached",
  );
});

test("POST /quorum avec un seuil sous le plancher relaie le refus 400 d'admin-api", async () => {
  await withServers(
    "allow",
    async (base) => {
      const cookie = await loginAndGetCookie(base);

      const form = new URLSearchParams({
        operation_id: "op-1",
        threshold: "1",
        expected_authority_domain: "admin-api",
        assertions: "AQID",
      });
      const submit = await request(base, "POST", "/quorum", {
        body: form.toString(),
        headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      });
      assert.equal(submit.status, 400);
      assert.match(submit.text, /seuil_de_quorum_invalide/);
    },
    "threshold-too-low",
  );
});

test("POST /quorum avec une assertion mal encodée est refusé avant tout appel à admin-api", async () => {
  await withServers("allow", async (base) => {
    const cookie = await loginAndGetCookie(base);

    const form = new URLSearchParams({
      operation_id: "op-1",
      threshold: "2",
      expected_authority_domain: "admin-api",
      assertions: "ceci n'est pas du base64 !!",
    });
    const submit = await request(base, "POST", "/quorum", {
      body: form.toString(),
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(submit.status, 400);
    assert.match(submit.text, /assertion_encodee_en_base64_invalide/);
  });
});

test("POST /quorum sans session redirige vers /login", async () => {
  await withServers("allow", async (base) => {
    const form = new URLSearchParams({
      operation_id: "op-1",
      threshold: "2",
      expected_authority_domain: "admin-api",
      assertions: "AQID",
    });
    const submit = await request(base, "POST", "/quorum", {
      body: form.toString(),
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(submit.status, 302);
    assert.equal(submit.headers.get("location"), "/login");
  });
});
