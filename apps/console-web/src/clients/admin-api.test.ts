import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { HttpAdminApiClient, AdminApiError } from "./admin-api.js";

async function listenEphemeral(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

test("requestQuorum encode les assertions en base64 standard et lit le résultat", async () => {
  let received: unknown;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    received = {
      url: req.url,
      assertionAppelant: req.headers["x-identity-assertion"],
      body: JSON.parse(Buffer.concat(chunks).toString("utf-8")),
    };
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ reached: true, distinct_subjects: ["subject-1", "subject-2"] }));
  });
  const base = await listenEphemeral(server);
  const client = new HttpAdminApiClient(base);

  const result = await client.requestQuorum(new Uint8Array([9, 9, 9]), {
    operationId: "op-1",
    assertions: [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])],
    threshold: 2,
    expectedAuthorityDomain: "admin-api",
  });

  // ADR-035 : sans cet en-tete, admin-api refuse en 401 et le parcours quorum de la console est
  // mort. Le client doit le poser systematiquement, encode en base64 comme pour access-broker.
  assert.equal(
    (received as { assertionAppelant?: string }).assertionAppelant,
    Buffer.from([9, 9, 9]).toString("base64"),
    "l'assertion de l'appelant doit etre transmise en en-tete X-Identity-Assertion",
  );
  assert.equal(result.reached, true);
  assert.deepEqual(result.distinctSubjects, ["subject-1", "subject-2"]);

  const req = received as { url: string; body: Record<string, unknown> };
  assert.equal(req.url, "/v1/critical-operations/op-1/quorum");
  assert.deepEqual(req.body["assertions"], [
    Buffer.from([1, 2, 3]).toString("base64"),
    Buffer.from([4, 5, 6]).toString("base64"),
  ]);
  assert.equal(req.body["threshold"], 2);

  server.close();
});

test("requestQuorum échoue avec AdminApiError sur un refus (seuil sous plancher)", async () => {
  const server = createServer((req, res) => {
    res.statusCode = 400;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ reason: "seuil_de_quorum_invalide" }));
  });
  const base = await listenEphemeral(server);
  const client = new HttpAdminApiClient(base);

  await assert.rejects(
    client.requestQuorum(new Uint8Array([9, 9, 9]), {
      operationId: "op-1",
      assertions: [new Uint8Array([1])],
      threshold: 1,
      expectedAuthorityDomain: "admin-api",
    }),
    (err: unknown) => {
      assert.ok(err instanceof AdminApiError);
      assert.equal(err.status, 400);
      assert.equal(err.reason, "seuil_de_quorum_invalide");
      return true;
    },
  );

  server.close();
});

test("requestQuorum encode l'operation_id dans l'URL", async () => {
  let receivedUrl: string | undefined;
  const server = createServer((req, res) => {
    receivedUrl = req.url;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ reached: false, distinct_subjects: [] }));
  });
  const base = await listenEphemeral(server);
  const client = new HttpAdminApiClient(base);

  await client.requestQuorum(new Uint8Array([9, 9, 9]), {
    operationId: "op with spaces/slash",
    assertions: [new Uint8Array([1])],
    threshold: 2,
    expectedAuthorityDomain: "admin-api",
  });

  assert.equal(receivedUrl, "/v1/critical-operations/op%20with%20spaces%2Fslash/quorum");
  server.close();
});
