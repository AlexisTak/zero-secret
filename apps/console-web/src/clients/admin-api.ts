// Client HTTP fin vers admin-api (contracts/openapi/admin-api.yaml). Encodage base64 STANDARD
// pour les champs `format: byte` — même famille que access-broker, DIFFÉRENT du base64url sans
// padding d'identity-provider (voir clients/identity-provider.ts). Ne jamais mélanger (ADR-024).

function b64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export interface QuorumInput {
  operationId: string;
  assertions: Uint8Array[];
  threshold: number;
  expectedAuthorityDomain: string;
}

export interface QuorumResult {
  reached: boolean;
  distinctSubjects: string[];
}

export class AdminApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: string,
  ) {
    super(`admin-api a refusé (${status}) : ${reason}`);
  }
}

export class HttpAdminApiClient {
  constructor(private readonly baseUrl: string) {}

  /** Chaque assertion est rejouée telle quelle — console-web ne les vérifie ni ne les
   * réinterprète, admin-api revérifie chacune via identity-provider (ADR-021/ADR-024).
   *
   * `identityAssertion` est celle de l'APPELANT, rejouée depuis la session et transmise en
   * en-tête : depuis ADR-035, admin-api refuse (401) tout déclenchement de quorum par un
   * appelant anonyme. Elle n'est jamais comptée parmi les porteurs. */
  async requestQuorum(identityAssertion: Uint8Array, input: QuorumInput): Promise<QuorumResult> {
    const response = await fetch(
      new URL(
        `/v1/critical-operations/${encodeURIComponent(input.operationId)}/quorum`,
        this.baseUrl,
      ),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Identity-Assertion": b64Encode(identityAssertion),
        },
        body: JSON.stringify({
          assertions: input.assertions.map(b64Encode),
          threshold: input.threshold,
          expected_authority_domain: input.expectedAuthorityDomain,
        }),
      },
    );
    const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) {
      const reason = typeof json["reason"] === "string" ? json["reason"] : response.statusText;
      throw new AdminApiError(response.status, reason);
    }
    return {
      reached: Boolean(json["reached"]),
      distinctSubjects: Array.isArray(json["distinct_subjects"])
        ? (json["distinct_subjects"] as string[])
        : [],
    };
  }
}
