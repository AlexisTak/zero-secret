// Session opaque côté serveur (ADR-024, security/threat-models/console-web.md). Jeton 256 bits
// (`crypto.randomBytes`, liste blanche fermée ADR-024 — jamais `sign`/`createCipheriv` ici) ;
// aucun contenu métier n'est porté par le jeton lui-même (pas de JWT) — seule la Map en mémoire
// fait foi, mono-instance, portée assumée (même famille que ConsumedDecisionStore, L2.4).

import { randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "__Host-session";

export interface SessionData {
  subjectId: string;
  /** Assertion identity-assertion/v1 scellée par identity-provider — opaque ici, jamais
   * réinterprétée : console-web ne vérifie jamais une assertion, elle la relaie (ADR-024). */
  identityAssertion: Uint8Array;
  /** Autorité qui fait foi pour l'expiration — jamais le Max-Age du cookie seul (ADR-024). */
  expiresAt: number;
}

interface StoredSession extends SessionData {
  id: string;
}

export class SessionStore {
  private readonly sessions = new Map<string, StoredSession>();
  private sweepTimer: NodeJS.Timeout | undefined;

  /** Purge active périodique — sans elle la Map grossit sans borne (DoS mémoire, ADR-024). */
  startSweeping(intervalMs: number): void {
    this.stopSweeping();
    this.sweepTimer = setInterval(() => this.sweepExpired(), intervalMs);
    this.sweepTimer.unref();
  }

  stopSweeping(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = undefined;
    }
  }

  sweepExpired(now: number = Date.now()): number {
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /** Crée une nouvelle session — toujours un identifiant frais, jamais réutilisé (anti-fixation :
   * l'appelant doit appeler ceci à chaque ré-authentification réussie, pas seulement la première). */
  create(data: SessionData): string {
    const id = randomBytes(32).toString("base64url");
    this.sessions.set(id, { id, ...data });
    return id;
  }

  /** Retourne la session si l'identifiant existe, correspond en temps constant et n'est pas
   * expirée — jamais un accès direct à la Map par l'appelant, pour garder ce contrôle unique. */
  get(id: string, now: number = Date.now()): SessionData | undefined {
    const found = this.lookupConstantTime(id);
    if (!found) return undefined;
    if (found.expiresAt <= now) {
      this.sessions.delete(found.id);
      return undefined;
    }
    return found;
  }

  destroy(id: string): void {
    const found = this.lookupConstantTime(id);
    if (found) this.sessions.delete(found.id);
  }

  get size(): number {
    return this.sessions.size;
  }

  /** Comparaison en temps constant de l'identifiant présenté contre chaque clé connue — un
   * identifiant de session est une valeur d'authentification au même titre qu'un secret, une
   * comparaison `Map.get` (donc `===` sur la clé) ne fuit rien de plus ici puisque `Map.get` est
   * déjà en O(1) par hachage, pas par comparaison caractère à caractère — mais on documente et on
   * borne explicitement pour ne jamais dépendre d'un détail d'implémentation du moteur JS. */
  private lookupConstantTime(id: string): StoredSession | undefined {
    let presented: Buffer;
    try {
      presented = Buffer.from(id, "base64url");
    } catch {
      return undefined;
    }
    if (presented.length !== 32) return undefined;
    for (const session of this.sessions.values()) {
      const known = Buffer.from(session.id, "base64url");
      if (known.length === presented.length && timingSafeEqual(known, presented)) {
        return session;
      }
    }
    return undefined;
  }
}

export interface CookieOptions {
  maxAgeSeconds: number;
}

export function setCookieHeader(sessionId: string, options: CookieOptions): string {
  return [
    `${SESSION_COOKIE_NAME}=${sessionId}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${options.maxAgeSeconds}`,
  ].join("; ");
}

export function clearCookieHeader(): string {
  return [`${SESSION_COOKIE_NAME}=`, "HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=0"].join(
    "; ",
  );
}

export function readSessionCookie(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === SESSION_COOKIE_NAME) return rest.join("=");
  }
  return undefined;
}
