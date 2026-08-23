// Client HTTP fin vers access-broker (contracts/openapi/access-broker.yaml). Encodage base64
// STANDARD pour les champs `format: byte` — DIFFÉRENT du base64url sans padding d'identity-
// provider (voir clients/identity-provider.ts). Ne jamais réutiliser l'un pour l'autre (ADR-024).

function b64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export interface AccessRequestInput {
  verb: string;
  resource: {
    type: string;
    id: string;
    authorityDomain: string;
  };
  justification: string;
  ticketRef: string;
  expectedAuthorityDomain: string;
}

export interface Decision {
  allowed: boolean;
  reasons: string[];
  policyVersion?: string;
}

export class HttpAccessBrokerClient {
  constructor(private readonly baseUrl: string) {}

  /** `identityAssertion` est rejouée telle quelle depuis la session — console-web ne la
   * réinterprète jamais, elle la transmet en en-tête (ADR-024). */
  async requestAccess(identityAssertion: Uint8Array, input: AccessRequestInput): Promise<Decision> {
    const response = await fetch(new URL("/v1/access-requests", this.baseUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Identity-Assertion": b64Encode(identityAssertion),
      },
      body: JSON.stringify({
        verb: input.verb,
        resource: {
          type: input.resource.type,
          id: input.resource.id,
          authority_domain: input.resource.authorityDomain,
        },
        justification: input.justification,
        ticket_ref: input.ticketRef,
        expected_authority_domain: input.expectedAuthorityDomain,
      }),
    });
    const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (response.status === 401) {
      throw new AccessBrokerAuthError(
        typeof json["reason"] === "string" ? json["reason"] : response.statusText,
      );
    }
    if (!response.ok) {
      const reason = typeof json["reason"] === "string" ? json["reason"] : response.statusText;
      throw new Error(`access-broker a refusé (${response.status}) : ${reason}`);
    }
    const policyVersion = json["policy_version"];
    return {
      allowed: Boolean(json["allowed"]),
      reasons: Array.isArray(json["reasons"]) ? (json["reasons"] as string[]) : [],
      ...(typeof policyVersion === "string" ? { policyVersion } : {}),
    };
  }
}

/** Distinct d'une erreur générique : le serveur (server.ts) doit détruire la session et effacer
 * le cookie sur ce cas précis (ADR-024 : 401 en aval → suppression serveur puis effacement). */
export class AccessBrokerAuthError extends Error {
  constructor(public readonly reason: string) {
    super(`assertion refusée par access-broker : ${reason}`);
  }
}
