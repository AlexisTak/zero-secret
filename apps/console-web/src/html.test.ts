import { test } from "node:test";
import assert from "node:assert/strict";

import { html, escapeHtml, raw } from "./html.js";

test("escapeHtml échappe les cinq caractères sensibles", () => {
  assert.equal(escapeHtml(`<script>"'&`), "&lt;script&gt;&quot;&#39;&amp;");
});

test("html échappe une valeur interpolée hostile", () => {
  const attacker = '<img src=x onerror="alert(1)">';
  const out = html`<p>${attacker}</p>`;
  assert.ok(!out.includes("<img"));
  assert.ok(out.includes("&lt;img"));
});

test("html laisse passer un fragment marqué raw() sans l'échapper", () => {
  const out = html`<ul>${raw("<li>x</li>")}</ul>`;
  assert.equal(out, "<ul><li>x</li></ul>");
});

test("html échappe chaque élément d'un tableau de chaînes", () => {
  const out = html`<ul>${["<b>a</b>", "b"]}</ul>`;
  assert.equal(out, "<ul>&lt;b&gt;a&lt;/b&gt;b</ul>");
});

test("html ne double-échappe pas un tableau de fragments raw()", () => {
  const items = ["<b>a</b>", "b"].map((x) => raw(html`<li>${x}</li>`));
  const out = html`<ul>${items}</ul>`;
  assert.equal(out, "<ul><li>&lt;b&gt;a&lt;/b&gt;</li><li>b</li></ul>");
});
