package collector

import (
	"context"
	"testing"
)

// TestSecurityPayloadInjectionSQLTraverseCommeValeurOpaque envoie des payloads d'injection SQL
// classiques dans authority_domain — le champ qui atteint directement la requête paramétrée
// `WHERE authority_domain = $1` (internal/store/store.go:49) et `VALUES ($1,…,$12)` (:95). Avec le
// fakeStore existant (collector_test.go), on confirme que le Collector transmet la chaîne TELLE
// QUELLE à AppendInput.AuthorityDomain (aucune concaténation, aucune interprétation avant le
// store) — la garantie structurelle du paramétrage $1 est ainsi couverte sans exécuter Postgres.
func TestSecurityPayloadInjectionSQLTraverseCommeValeurOpaque(t *testing.T) {
	payloads := []string{
		`' OR '1'='1`,
		`'; DROP TABLE audit.events; --`,
		`x' UNION SELECT credential_id, public_key FROM identity.authenticators --`,
		`%27%20OR%20%271%27%3D%271`, // encodé URL
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			sealer := &fakeSealer{sealedOut: []byte("scelle-de-test")}
			st := &fakeStore{}
			c := New(sealer, st)

			raw := validRawEvent()
			raw.AuthorityDomain = payload

			result, err := c.Record(context.Background(), raw)
			if err != nil {
				t.Fatalf("Record ne doit jamais renvoyer d'erreur de transport pour ce payload : %v", err)
			}
			if !result.Accepted {
				t.Fatalf("Record doit accepter l'événement (le payload n'est pas un event_type/outcome invalide) : reason=%q", result.Reason)
			}
			if st.appendedIn == nil || st.appendedIn.AuthorityDomain != payload {
				t.Fatalf("Append doit recevoir AppendInput.AuthorityDomain = %q tel quel, obtenu %+v", payload, st.appendedIn)
			}
		})
	}
}
