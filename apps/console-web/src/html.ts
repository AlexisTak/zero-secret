// Échappement HTML systématique — pas de moteur de template externe (ADR-024, zéro dépendance
// runtime). Toute valeur interpolée dans un tagged template `html` est échappée par défaut ;
// `raw()` marque explicitement un fragment déjà sûr (littéral de balisage écrit ici, jamais une
// entrée utilisateur) — c'est la seule façon d'insérer du HTML non échappé, jamais implicite.

const ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ESCAPES[ch] ?? ch);
}

export class RawHtml {
  constructor(public readonly value: string) {}
}

export function raw(value: string): RawHtml {
  return new RawHtml(value);
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): string {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    if (value instanceof RawHtml) {
      out += value.value;
    } else if (Array.isArray(value)) {
      out += value
        .map((v) => (v instanceof RawHtml ? v.value : escapeHtml(String(v))))
        .join("");
    } else {
      out += escapeHtml(String(value));
    }
    out += strings[i + 1] ?? "";
  }
  return out;
}

export function page(title: string, body: string): string {
  return html`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
</head>
<body>
${raw(body)}
</body>
</html>`;
}
