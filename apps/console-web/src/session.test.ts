import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SessionStore,
  setCookieHeader,
  clearCookieHeader,
  readSessionCookie,
  SESSION_COOKIE_NAME,
} from "./session.js";

function sampleData(overrides: Partial<{ expiresAt: number }> = {}) {
  return {
    subjectId: "subject-1",
    identityAssertion: new Uint8Array([1, 2, 3]),
    expiresAt: overrides.expiresAt ?? Date.now() + 60_000,
  };
}

test("create puis get retourne la session tant qu'elle n'a pas expiré", () => {
  const store = new SessionStore();
  const id = store.create(sampleData());
  const found = store.get(id);
  assert.equal(found?.subjectId, "subject-1");
});

test("get refuse un identifiant inconnu", () => {
  const store = new SessionStore();
  store.create(sampleData());
  assert.equal(store.get("aW52YWxpZGUtaW52YWxpZGUtaW52YWxpZGUtaW52YWxpZGU"), undefined);
});

// --- cas adverses ------------------------------------------------------------------------
test("get refuse une session expirée et la supprime", () => {
  const store = new SessionStore();
  const id = store.create(sampleData({ expiresAt: Date.now() - 1 }));
  assert.equal(store.get(id), undefined);
  assert.equal(store.size, 0);
});

test("destroy rend la session immédiatement introuvable", () => {
  const store = new SessionStore();
  const id = store.create(sampleData());
  store.destroy(id);
  assert.equal(store.get(id), undefined);
});

test("chaque create() produit un identifiant différent (anti-fixation)", () => {
  const store = new SessionStore();
  const id1 = store.create(sampleData());
  const id2 = store.create(sampleData());
  assert.notEqual(id1, id2);
});

test("sweepExpired purge uniquement les entrées expirées", () => {
  const store = new SessionStore();
  const now = Date.now();
  store.create(sampleData({ expiresAt: now - 1 }));
  const keepId = store.create(sampleData({ expiresAt: now + 60_000 }));
  const removed = store.sweepExpired(now);
  assert.equal(removed, 1);
  assert.equal(store.size, 1);
  assert.ok(store.get(keepId));
});

test("un identifiant malformé (mauvaise longueur) est refusé sans lever", () => {
  const store = new SessionStore();
  store.create(sampleData());
  assert.equal(store.get("trop-court"), undefined);
});

// --- cookies --------------------------------------------------------------------------------
test("setCookieHeader pose HttpOnly, Secure, SameSite=Strict et le préfixe __Host-", () => {
  const header = setCookieHeader("abc", { maxAgeSeconds: 120 });
  assert.match(header, new RegExp(`^${SESSION_COOKIE_NAME}=abc;`));
  assert.match(header, /HttpOnly/);
  assert.match(header, /Secure/);
  assert.match(header, /SameSite=Strict/);
  assert.match(header, /Max-Age=120/);
});

test("clearCookieHeader met Max-Age=0", () => {
  assert.match(clearCookieHeader(), /Max-Age=0/);
});

test("readSessionCookie extrait la valeur parmi plusieurs cookies", () => {
  const header = `autre=x; ${SESSION_COOKIE_NAME}=le-jeton; encore=y`;
  assert.equal(readSessionCookie(header), "le-jeton");
});

test("readSessionCookie renvoie undefined si l'en-tête est absent", () => {
  assert.equal(readSessionCookie(undefined), undefined);
});
