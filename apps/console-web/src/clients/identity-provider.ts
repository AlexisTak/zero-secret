// Client HTTP fin vers identity-provider (H5, contracts/openapi/identity-provider.yaml).
// Encodage base64url SANS padding pour tous les champs `format: byte` — documenté explicitement
// dans ce contrat, DIFFÉRENT du base64 standard utilisé par access-broker (voir
// clients/access-broker.ts). Ne jamais réutiliser l'un pour l'autre (ADR-024).

function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function b64urlDecode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export interface IdentityProviderClient {
  registrationChallenge(subjectId: string): Promise<{
    challenge: string;
    rpId: string;
    expiresAt: string;
  }>;
  registrationVerify(clientDataJson: Uint8Array, attestationObject: Uint8Array): Promise<{
    credentialId: Uint8Array;
  }>;
  authenticationChallenge(subjectId: string): Promise<{
    challenge: string;
    rpId: string;
    expiresAt: string;
    allowCredentials: Uint8Array[];
  }>;
  authenticationVerify(input: {
    credentialId: Uint8Array;
    clientDataJson: Uint8Array;
    authenticatorData: Uint8Array;
    signature: Uint8Array;
  }): Promise<{ assertion: Uint8Array }>;
}

export class HttpIdentityProviderClient implements IdentityProviderClient {
  constructor(private readonly baseUrl: string) {}

  private async post(path: string, body: unknown): Promise<Record<string, unknown>> {
    const response = await fetch(new URL(path, this.baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) {
      const reason = typeof json["reason"] === "string" ? json["reason"] : response.statusText;
      throw new IdentityProviderError(response.status, reason);
    }
    return json;
  }

  async registrationChallenge(subjectId: string) {
    const json = await this.post("/v1/webauthn/registration/challenge", { subject_id: subjectId });
    return {
      challenge: json["challenge"] as string,
      rpId: json["rp_id"] as string,
      expiresAt: json["expires_at"] as string,
    };
  }

  async registrationVerify(clientDataJson: Uint8Array, attestationObject: Uint8Array) {
    const json = await this.post("/v1/webauthn/registration/verify", {
      client_data_json: b64urlEncode(clientDataJson),
      attestation_object: b64urlEncode(attestationObject),
    });
    return { credentialId: b64urlDecode(json["credential_id"] as string) };
  }

  async authenticationChallenge(subjectId: string) {
    const json = await this.post("/v1/webauthn/authentication/challenge", {
      subject_id: subjectId,
    });
    return {
      challenge: json["challenge"] as string,
      rpId: json["rp_id"] as string,
      expiresAt: json["expires_at"] as string,
      allowCredentials: (json["allow_credentials"] as string[]).map(b64urlDecode),
    };
  }

  async authenticationVerify(input: {
    credentialId: Uint8Array;
    clientDataJson: Uint8Array;
    authenticatorData: Uint8Array;
    signature: Uint8Array;
  }) {
    const json = await this.post("/v1/webauthn/authentication/verify", {
      credential_id: b64urlEncode(input.credentialId),
      client_data_json: b64urlEncode(input.clientDataJson),
      authenticator_data: b64urlEncode(input.authenticatorData),
      signature: b64urlEncode(input.signature),
    });
    return { assertion: b64urlDecode(json["assertion"] as string) };
  }
}

export class IdentityProviderError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: string,
  ) {
    super(`identity-provider a refusé (${status}) : ${reason}`);
  }
}
