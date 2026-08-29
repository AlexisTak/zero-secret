// Serveur BFF (backend-for-frontend, ADR-024) — rend le HTML et fait les appels HTTP serveur-
// à-serveur ; le navigateur ne voit jamais l'assertion identity-assertion/v1 en clair, seulement
// un cookie de session opaque. La cérémonie WebAuthn (navigator.credentials.create/get) est
// déclenchée par public/webauthn.ts côté navigateur, mais ne contient aucune logique de
// sécurité — elle relaie juste le résultat brut au serveur (docs/architecture.md : « aucune
// logique de sécurité côté client »).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { html, page, escapeHtml, raw } from "./html.js";
import {
  SessionStore,
  readSessionCookie,
  setCookieHeader,
  clearCookieHeader,
} from "./session.js";
import type { IdentityProviderClient } from "./clients/identity-provider.js";
import { HttpAccessBrokerClient, AccessBrokerAuthError } from "./clients/access-broker.js";
import { HttpAdminApiClient, AdminApiError, type QuorumResult } from "./clients/admin-api.js";

export interface ServerConfig {
  origin: string;
  identityProvider: IdentityProviderClient;
  accessBroker: HttpAccessBrokerClient;
  adminApi: HttpAdminApiClient;
  expectedAuthorityDomain: string;
  sessionTtlSeconds: number;
  publicDir: string;
}

export function createApp(config: ServerConfig) {
  const sessions = new SessionStore();
  sessions.startSweeping(30_000);

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method ?? "GET";

    // CSRF : SameSite=Strict seul ne suffit pas (ADR-024) — vérifier l'origine sur tout POST.
    if (method === "POST" && !isSameOrigin(req, config.origin)) {
      send(res, 403, { reason: "origine_inattendue" });
      return;
    }

    try {
      if (method === "GET" && url.pathname === "/register") return sendPage(res, registerPage());
      if (method === "GET" && url.pathname === "/login") return sendPage(res, loginPage());
      if (method === "GET" && url.pathname === "/access-request") {
        return handleAccessRequestPage(req, res, sessions);
      }
      if (method === "GET" && url.pathname === "/quorum") {
        return handleQuorumPage(req, res, sessions);
      }
      if (method === "GET" && url.pathname.startsWith("/static/")) {
        return serveStatic(res, url.pathname, config.publicDir);
      }

      if (method === "POST" && url.pathname === "/api/webauthn/registration/challenge") {
        return handleJson(req, res, async (body) => {
          const subjectId = requireString(body, "subject_id");
          return config.identityProvider.registrationChallenge(subjectId);
        });
      }
      if (method === "POST" && url.pathname === "/api/webauthn/registration/verify") {
        return handleJson(req, res, async (body) => {
          const outcome = await config.identityProvider.registrationVerify(
            b64urlToBytes(requireString(body, "client_data_json")),
            b64urlToBytes(requireString(body, "attestation_object")),
          );
          return { credential_id: bytesToB64url(outcome.credentialId) };
        });
      }
      if (method === "POST" && url.pathname === "/api/webauthn/authentication/challenge") {
        return handleJson(req, res, async (body) => {
          const subjectId = requireString(body, "subject_id");
          const outcome = await config.identityProvider.authenticationChallenge(subjectId);
          return {
            challenge: outcome.challenge,
            rp_id: outcome.rpId,
            expires_at: outcome.expiresAt,
            allow_credentials: outcome.allowCredentials.map(bytesToB64url),
            subject_id: subjectId,
          };
        });
      }
      if (method === "POST" && url.pathname === "/api/webauthn/authentication/verify") {
        return handleAuthenticationVerify(req, res, config, sessions);
      }
      if (method === "POST" && url.pathname === "/access-request") {
        return handleAccessRequestSubmit(req, res, config, sessions);
      }
      if (method === "POST" && url.pathname === "/quorum") {
        return handleQuorumSubmit(req, res, config, sessions);
      }
      if (method === "POST" && url.pathname === "/logout") {
        return handleLogout(req, res, sessions);
      }

      send(res, 404, { reason: "introuvable" });
    } catch (err) {
      // Jamais de détail interne exposé (message d'erreur brut) — un refus générique, l'erreur
      // réelle reste côté serveur (pas de journalisation de contenu de session, ADR-024).
      res.statusCode = 500;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ reason: "erreur_interne" }));
      // eslint-disable-next-line no-console
      console.error("console-web: erreur non gérée", err);
    }
  }

  return createServer((req, res) => {
    void handle(req, res);
  });
}

function isSameOrigin(req: IncomingMessage, expectedOrigin: string): boolean {
  const secFetchSite = req.headers["sec-fetch-site"];
  if (secFetchSite === "same-origin" || secFetchSite === "none") return true;
  const origin = req.headers["origin"];
  if (typeof origin === "string") return origin === expectedOrigin;
  // Ni Sec-Fetch-Site ni Origin (navigateur ancien) : refus par défaut, jamais une exception
  // silencieuse pour compatibilité (règle absolue #2).
  return false;
}

function send(res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  for (const [k, v] of Object.entries(extraHeaders ?? {})) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

function sendPage(res: ServerResponse, body: string, status = 200): void {
  res.statusCode = status;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  if (raw.length === 0) return {};
  return JSON.parse(raw);
}

async function readFormBody(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  const params = new URLSearchParams(raw);
  const out: Record<string, string> = {};
  for (const [key, value] of params) out[key] = value;
  return out;
}

function requireString(body: unknown, field: string): string {
  const value = (body as Record<string, unknown>)?.[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new BadRequest(`champ_manquant_ou_invalide:${field}`);
  }
  return value;
}

class BadRequest extends Error {}

async function handleJson(
  req: IncomingMessage,
  res: ServerResponse,
  fn: (body: unknown) => Promise<unknown>,
): Promise<void> {
  try {
    const body = await readBody(req);
    const result = await fn(body);
    send(res, 200, result);
  } catch (err) {
    if (err instanceof BadRequest) {
      send(res, 400, { reason: err.message });
      return;
    }
    const status = (err as { status?: number })?.status;
    const reason = (err as { reason?: string })?.reason ?? "requete_refusee";
    send(res, typeof status === "number" ? status : 502, { reason });
  }
}

async function handleAuthenticationVerify(
  req: IncomingMessage,
  res: ServerResponse,
  config: ServerConfig,
  sessions: SessionStore,
): Promise<void> {
  try {
    const body = (await readBody(req)) as Record<string, unknown>;
    const subjectId = requireString(body, "subject_id");
    const outcome = await config.identityProvider.authenticationVerify({
      credentialId: b64urlToBytes(requireString(body, "credential_id")),
      clientDataJson: b64urlToBytes(requireString(body, "client_data_json")),
      authenticatorData: b64urlToBytes(requireString(body, "authenticator_data")),
      signature: b64urlToBytes(requireString(body, "signature")),
    });

    // Identifiant de session frais à chaque authentification réussie — jamais réutilisé
    // (anti-fixation, ADR-024).
    const sessionId = sessions.create({
      subjectId,
      identityAssertion: outcome.assertion,
      expiresAt: Date.now() + config.sessionTtlSeconds * 1000,
    });

    send(res, 200, { redirect: "/access-request" }, {
      "set-cookie": setCookieHeader(sessionId, { maxAgeSeconds: config.sessionTtlSeconds }),
    });
  } catch (err) {
    const status = (err as { status?: number })?.status;
    const reason = (err as { reason?: string })?.reason ?? "authentification_refusee";
    send(res, typeof status === "number" ? status : 401, { reason });
  }
}

function requireSession(req: IncomingMessage, sessions: SessionStore) {
  const sessionId = readSessionCookie(req.headers["cookie"]);
  if (!sessionId) return undefined;
  return sessions.get(sessionId);
}

async function handleAccessRequestPage(
  req: IncomingMessage,
  res: ServerResponse,
  sessions: SessionStore,
): Promise<void> {
  const session = requireSession(req, sessions);
  if (!session) {
    res.statusCode = 302;
    res.setHeader("location", "/login");
    res.end();
    return;
  }
  sendPage(res, accessRequestPage(session.subjectId));
}

async function handleAccessRequestSubmit(
  req: IncomingMessage,
  res: ServerResponse,
  config: ServerConfig,
  sessions: SessionStore,
): Promise<void> {
  const sessionId = readSessionCookie(req.headers["cookie"]);
  const session = sessionId ? sessions.get(sessionId) : undefined;
  if (!session) {
    res.statusCode = 302;
    res.setHeader("location", "/login");
    res.end();
    return;
  }

  try {
    const body = await readFormBody(req);
    const decision = await config.accessBroker.requestAccess(session.identityAssertion, {
      verb: requireString(body, "verb"),
      resource: {
        type: requireString(body, "resource_type"),
        id: requireString(body, "resource_id"),
        authorityDomain: requireString(body, "resource_authority_domain"),
      },
      justification: requireString(body, "justification"),
      ticketRef: requireString(body, "ticket_ref"),
      expectedAuthorityDomain: config.expectedAuthorityDomain,
    });
    sendPage(res, accessDecisionPage(session.subjectId, decision));
  } catch (err) {
    if (err instanceof AccessBrokerAuthError) {
      // 401 en aval : suppression de l'entrée serveur PUIS effacement du cookie, dans cet
      // ordre — jamais l'inverse (ADR-024).
      if (sessionId) sessions.destroy(sessionId);
      res.setHeader("set-cookie", clearCookieHeader());
      res.statusCode = 302;
      res.setHeader("location", "/login");
      res.end();
      return;
    }
    if (err instanceof BadRequest) {
      sendPage(res, page("Demande refusée", html`<p>Requête invalide : ${err.message}</p>`), 400);
      return;
    }
    sendPage(res, page("Service indisponible", html`<p>access-broker est indisponible.</p>`), 502);
  }
}

async function handleQuorumPage(
  req: IncomingMessage,
  res: ServerResponse,
  sessions: SessionStore,
): Promise<void> {
  const session = requireSession(req, sessions);
  if (!session) {
    res.statusCode = 302;
    res.setHeader("location", "/login");
    res.end();
    return;
  }
  sendPage(res, quorumPage());
}

/** Parse le bloc "une assertion base64 standard par ligne" — lignes vides ignorées, jamais
 * transmises telles quelles sans validation de décodabilité (ADR-024 : ne jamais faire confiance
 * à une entrée non fiable sans la valider avant de la relayer). */
function parseAssertionsBlock(raw: string): Uint8Array[] {
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (lines.length === 0) {
    throw new BadRequest("champ_manquant_ou_invalide:assertions");
  }
  return lines.map((line) => {
    // Buffer.from(..., "base64") ignore silencieusement les caractères hors alphabet plutôt que
    // de rejeter — revalider explicitement par ré-encodage (comparaison sans le padding, que
    // l'opérateur peut omettre) avant de faire confiance à la valeur décodée (ADR-024).
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(line)) {
      throw new BadRequest("assertion_encodee_en_base64_invalide");
    }
    const decoded = Buffer.from(line, "base64");
    const reencoded = decoded.toString("base64").replace(/=+$/, "");
    if (reencoded !== line.replace(/=+$/, "")) {
      throw new BadRequest("assertion_encodee_en_base64_invalide");
    }
    return new Uint8Array(decoded);
  });
}

async function handleQuorumSubmit(
  req: IncomingMessage,
  res: ServerResponse,
  config: ServerConfig,
  sessions: SessionStore,
): Promise<void> {
  const session = requireSession(req, sessions);
  if (!session) {
    res.statusCode = 302;
    res.setHeader("location", "/login");
    res.end();
    return;
  }

  try {
    const body = await readFormBody(req);
    const operationId = requireString(body, "operation_id");
    const thresholdRaw = requireString(body, "threshold");
    const threshold = Number(thresholdRaw);
    if (!Number.isInteger(threshold)) {
      throw new BadRequest("champ_manquant_ou_invalide:threshold");
    }
    const assertions = parseAssertionsBlock(requireString(body, "assertions"));

    const result = await config.adminApi.requestQuorum(session.identityAssertion, {
      operationId,
      assertions,
      threshold,
      expectedAuthorityDomain: requireString(body, "expected_authority_domain"),
    });
    sendPage(res, quorumResultPage(operationId, result));
  } catch (err) {
    if (err instanceof AdminApiError) {
      sendPage(
        res,
        page("Quorum refusé", html`<p>${err.reason}</p><p><a href="/quorum">Retour</a></p>`),
        err.status,
      );
      return;
    }
    if (err instanceof BadRequest) {
      sendPage(
        res,
        page(
          "Quorum refusé",
          html`<p>Requête invalide : ${err.message}</p><p><a href="/quorum">Retour</a></p>`,
        ),
        400,
      );
      return;
    }
    sendPage(res, page("Service indisponible", html`<p>admin-api est indisponible.</p>`), 502);
  }
}

async function handleLogout(
  req: IncomingMessage,
  res: ServerResponse,
  sessions: SessionStore,
): Promise<void> {
  const sessionId = readSessionCookie(req.headers["cookie"]);
  if (sessionId) sessions.destroy(sessionId);
  send(res, 200, { ok: true }, { "set-cookie": clearCookieHeader() });
}

async function serveStatic(res: ServerResponse, pathname: string, publicDir: string): Promise<void> {
  const rel = pathname.replace(/^\/static\//, "");
  // Refus explicite de toute tentative de sortir de publicDir (ADR-024, entrée non fiable).
  if (rel.includes("..") || path.isAbsolute(rel)) {
    send(res, 400, { reason: "chemin_invalide" });
    return;
  }
  const filePath = path.join(publicDir, rel);
  try {
    const data = await readFile(filePath);
    res.statusCode = 200;
    res.setHeader("content-type", rel.endsWith(".js") ? "text/javascript" : "application/octet-stream");
    res.end(data);
  } catch {
    send(res, 404, { reason: "introuvable" });
  }
}

function b64urlToBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function bytesToB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// --- pages -----------------------------------------------------------------------------------

function registerPage(): string {
  return page(
    "Enregistrement — console",
    html`<h1>Enregistrement d'un authentificateur</h1>
<p>Le sujet est accepté tel quel dans ce lot — aucun mécanisme d'invitation n'est instruit
   (ADR-023, angle mort documenté).</p>
<form id="register-form">
<label>Identifiant du sujet <input type="text" name="subject_id" required autocomplete="username"></label>
<button type="submit">S'enregistrer</button>
</form>
<p id="register-status" role="status"></p>
<script type="module" src="/static/webauthn.js" data-flow="register"></script>`,
  );
}

function loginPage(): string {
  return page(
    "Connexion — console",
    html`<h1>Connexion</h1>
<form id="login-form">
<label>Identifiant du sujet <input type="text" name="subject_id" required autocomplete="username"></label>
<button type="submit">Se connecter</button>
</form>
<p id="login-status" role="status"></p>
<script type="module" src="/static/webauthn.js" data-flow="login"></script>`,
  );
}

function navBar(subjectId: string): string {
  return html`<p>Connecté comme <strong>${subjectId}</strong> —
<a href="/access-request">Demande d'accès</a> · <a href="/quorum">Quorum</a> ·
<form method="post" action="/logout" style="display:inline"><button type="submit">Se déconnecter</button></form></p>`;
}

function accessRequestPage(subjectId: string): string {
  return page(
    "Demande d'accès — console",
    html`<h1>Demande d'accès</h1>
${raw(navBar(subjectId))}
<form method="post" action="/access-request">
<label>Verbe <input type="text" name="verb" required placeholder="db.connect"></label>
<label>Type de ressource <input type="text" name="resource_type" required placeholder="Database"></label>
<label>Identifiant de ressource <input type="text" name="resource_id" required></label>
<label>Domaine d'autorité de la ressource <input type="text" name="resource_authority_domain" required></label>
<label>Justification <textarea name="justification" required maxlength="512"></textarea></label>
<label>Référence de ticket <input type="text" name="ticket_ref" required></label>
<button type="submit">Demander l'accès</button>
</form>`,
  );
}

function accessDecisionPage(subjectId: string, decision: { allowed: boolean; reasons: string[] }): string {
  return page(
    "Décision — console",
    html`<h1>${decision.allowed ? "Accès autorisé" : "Accès refusé"}</h1>
<p>Connecté comme <strong>${subjectId}</strong></p>
<ul>${decision.reasons.map((r) => raw(html`<li>${r}</li>`))}</ul>
<p><a href="/access-request">Nouvelle demande</a></p>`,
  );
}

function quorumPage(): string {
  return page(
    "Quorum — console",
    html`<h1>Vérification de quorum</h1>
<p>Chaque assertion a déjà été réunie hors bande (une par porteur) — ce formulaire ne collecte
   rien en temps réel, il relaie un lot déjà complet vers admin-api (portée assumée, L2.6b).</p>
<form method="post" action="/quorum">
<label>Identifiant de l'opération <input type="text" name="operation_id" required></label>
<label>Seuil (minimum 2) <input type="number" name="threshold" min="2" value="2" required></label>
<label>Domaine d'autorité attendu <input type="text" name="expected_authority_domain" required></label>
<label>Assertions (une par ligne, base64 standard)
<textarea name="assertions" required rows="6"></textarea></label>
<button type="submit">Vérifier le quorum</button>
</form>
<p><a href="/access-request">Retour</a></p>`,
  );
}

function quorumResultPage(operationId: string, result: QuorumResult): string {
  return page(
    "Résultat du quorum — console",
    html`<h1>${result.reached ? "Quorum atteint" : "Quorum non atteint"}</h1>
<p>Opération <strong>${operationId}</strong></p>
<p>Porteurs distincts vérifiés :</p>
<ul>${result.distinctSubjects.map((s) => raw(html`<li>${s}</li>`))}</ul>
<p><a href="/quorum">Nouvelle vérification</a></p>`,
  );
}

export function escapeForTest(value: string): string {
  return escapeHtml(value);
}
