// Cérémonie WebAuthn côté navigateur — AUCUNE logique de sécurité ici (docs/architecture.md).
// Ce script ne fait que : demander un challenge au serveur, appeler navigator.credentials, et
// renvoyer le résultat brut au serveur. Il ne décide jamais si une assertion est valide — seul
// identity-provider (via console-web en relais) en décide.

function b64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function postJson(path: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) {
    throw new Error(typeof json["reason"] === "string" ? json["reason"] : "requête refusée");
  }
  return json;
}

async function runRegistration(subjectId: string, statusEl: HTMLElement): Promise<void> {
  const challengeResp = await postJson("/api/webauthn/registration/challenge", {
    subject_id: subjectId,
  });

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: b64urlToBuffer(challengeResp["challenge"] as string),
      rp: { id: challengeResp["rp_id"] as string, name: "zero-secret" },
      user: {
        id: new TextEncoder().encode(subjectId),
        name: subjectId,
        displayName: subjectId,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -8 }, // EdDSA
      ],
      authenticatorSelection: { userVerification: "preferred" },
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("cérémonie annulée");
  const response = credential.response as AuthenticatorAttestationResponse;

  await postJson("/api/webauthn/registration/verify", {
    client_data_json: bufferToB64url(response.clientDataJSON),
    attestation_object: bufferToB64url(response.attestationObject),
  });

  statusEl.textContent = "Enregistrement réussi — vous pouvez vous connecter.";
}

async function runAuthentication(subjectId: string, statusEl: HTMLElement): Promise<void> {
  const challengeResp = await postJson("/api/webauthn/authentication/challenge", {
    subject_id: subjectId,
  });
  const allowCredentials = (challengeResp["allow_credentials"] as string[]).map((id) => ({
    type: "public-key" as const,
    id: b64urlToBuffer(id),
  }));

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToBuffer(challengeResp["challenge"] as string),
      rpId: challengeResp["rp_id"] as string,
      allowCredentials,
      userVerification: "preferred",
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("cérémonie annulée");
  const response = credential.response as AuthenticatorAssertionResponse;

  const verifyResp = await postJson("/api/webauthn/authentication/verify", {
    subject_id: subjectId,
    credential_id: bufferToB64url(credential.rawId),
    client_data_json: bufferToB64url(response.clientDataJSON),
    authenticator_data: bufferToB64url(response.authenticatorData),
    signature: bufferToB64url(response.signature),
  });

  statusEl.textContent = "Connexion réussie, redirection…";
  window.location.href = (verifyResp["redirect"] as string) ?? "/access-request";
}

function currentScriptFlow(): string | null {
  const script = document.currentScript as HTMLScriptElement | null;
  return script?.dataset["flow"] ?? null;
}

function main(): void {
  const flow = currentScriptFlow();
  if (flow === "register") {
    const form = document.querySelector<HTMLFormElement>("#register-form");
    const status = document.querySelector<HTMLElement>("#register-status");
    form?.addEventListener("submit", (event) => {
      event.preventDefault();
      const subjectId = new FormData(form).get("subject_id");
      if (typeof subjectId !== "string" || !status) return;
      runRegistration(subjectId, status).catch((err: unknown) => {
        status.textContent = `Échec : ${err instanceof Error ? err.message : String(err)}`;
      });
    });
  } else if (flow === "login") {
    const form = document.querySelector<HTMLFormElement>("#login-form");
    const status = document.querySelector<HTMLElement>("#login-status");
    form?.addEventListener("submit", (event) => {
      event.preventDefault();
      const subjectId = new FormData(form).get("subject_id");
      if (typeof subjectId !== "string" || !status) return;
      runAuthentication(subjectId, status).catch((err: unknown) => {
        status.textContent = `Échec : ${err instanceof Error ? err.message : String(err)}`;
      });
    });
  }
}

main();
