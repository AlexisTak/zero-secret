// Tests d'intégration contre un vrai Postgres (schéma `audit`, migrations de deploy/migrations/
// appliquées) — jamais de mock de base de données (même discipline que le reste du dépôt).
// Ignorés (pas échoués) si ZS_AC_TEST_POSTGRES_DSN est absent — non vérifiés sur ce poste, à
// exécuter explicitement en CI/local avec `make up`, même patron que
// apps/identity-provider/tests/http_ceremony.rs (ZS_IDP_*_DATABASE_URL, require_env + #[ignore]).
package store

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("ZS_AC_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ZS_AC_TEST_POSTGRES_DSN absent — test d'intégration Postgres non exécuté sur ce poste")
	}
	st, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connexion : %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestChainHeadSansEvenementRenvoieLaRacine(t *testing.T) {
	st := testStore(t)
	domain := "test." + uuid.NewString()

	head, err := st.ChainHead(context.Background(), domain)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if head.NextSequence != 0 {
		t.Fatalf("séquence inattendue : %d", head.NextSequence)
	}
	if head.PrevSealedBytes != nil {
		t.Fatal("attendu aucun événement précédent")
	}
}

func TestAppendPuisChainHeadRenvoieLaSequenceSuivante(t *testing.T) {
	st := testStore(t)
	domain := "test." + uuid.NewString()

	err := st.Append(context.Background(), AppendInput{
		EventID:         uuid.NewString(),
		Sequence:        0,
		OccurredAt:      "2026-08-24T10:00:00Z",
		AuthorityDomain: domain,
		EventType:       "authentication.succeeded",
		ActorJSON:       []byte(`{"subject_id":"alice","kind":"human"}`),
		Outcome:         "success",
		PrevHashHex:     "00000000000000000000000000000000000000000000000000000000000000",
		SignatureJSON:   []byte(`{"suite":"audit-seal/v1"}`),
		SealedBytes:     []byte("octets-scelles"),
	})
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}

	head, err := st.ChainHead(context.Background(), domain)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if head.NextSequence != 1 {
		t.Fatalf("séquence suivante attendue : 1, obtenu : %d", head.NextSequence)
	}
	if string(head.PrevSealedBytes) != "octets-scelles" {
		t.Fatalf("sealed_bytes inattendus : %s", head.PrevSealedBytes)
	}
}

func TestAppendEnConflitDeSequenceEstRefuseSansReessai(t *testing.T) {
	st := testStore(t)
	domain := "test." + uuid.NewString()

	in := AppendInput{
		EventID:         uuid.NewString(),
		Sequence:        0,
		OccurredAt:      "2026-08-24T10:00:00Z",
		AuthorityDomain: domain,
		EventType:       "authentication.succeeded",
		ActorJSON:       []byte(`{"subject_id":"alice","kind":"human"}`),
		Outcome:         "success",
		PrevHashHex:     "00000000000000000000000000000000000000000000000000000000000000",
		SignatureJSON:   []byte(`{"suite":"audit-seal/v1"}`),
		SealedBytes:     []byte("premiers-octets"),
	}
	if err := st.Append(context.Background(), in); err != nil {
		t.Fatalf("premier ajout inattendu en échec : %v", err)
	}

	// Même (authority_domain, sequence) — la contrainte UNIQUE (migration 002) doit refuser,
	// jamais réattribuer silencieusement une nouvelle séquence (ADR-011 : seal() n'est pas
	// idempotent, un ré-essai produirait une seconde signature valide sur la même paire).
	conflict := in
	conflict.EventID = uuid.NewString()
	conflict.SealedBytes = []byte("seconds-octets-differents")
	if err := st.Append(context.Background(), conflict); err == nil {
		t.Fatal("attendu un refus sur conflit de séquence")
	}
}
