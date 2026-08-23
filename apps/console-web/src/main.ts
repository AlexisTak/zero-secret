import path from "node:path";
import { fileURLToPath } from "node:url";

import { createApp } from "./server.js";
import { HttpIdentityProviderClient } from "./clients/identity-provider.js";
import { HttpAccessBrokerClient } from "./clients/access-broker.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`console-web: variable d'environnement manquante : ${name}`);
    process.exit(1);
  }
  return value;
}

function envOr(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function main(): void {
  const port = Number(envOr("CONSOLE_WEB_PORT", "3000"));
  const origin = requireEnv("CONSOLE_WEB_ORIGIN");
  const identityProviderUrl = requireEnv("CONSOLE_WEB_IDENTITY_PROVIDER_URL");
  const accessBrokerUrl = requireEnv("CONSOLE_WEB_ACCESS_BROKER_URL");
  const expectedAuthorityDomain = envOr("CONSOLE_WEB_EXPECTED_AUTHORITY_DOMAIN", "access-broker");
  const sessionTtlSeconds = Number(envOr("CONSOLE_WEB_SESSION_TTL_SECONDS", "120"));

  const server = createApp({
    origin,
    identityProvider: new HttpIdentityProviderClient(identityProviderUrl),
    accessBroker: new HttpAccessBrokerClient(accessBrokerUrl),
    expectedAuthorityDomain,
    sessionTtlSeconds,
    publicDir: path.join(__dirname, "..", "public"),
  });

  server.listen(port, () => {
    // console-web n'a pas de TLS dans ce lot (même dette que partout ailleurs, ADR-024) — à
    // placer derrière un reverse proxy TLS avant tout déploiement réel.
    console.error(`console-web: en écoute sur :${port} (en clair — TLS hors périmètre)`);
  });
}

main();
