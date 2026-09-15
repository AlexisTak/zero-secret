package zstransport

import (
	"testing"

	"google.golang.org/grpc"
)

// grpc.NewClient exige des credentials de transport explicites : sans elles, il refuse de
// construire le client (« no transport security set »). Ce test fige que DialOptions() satisfait
// bien cette exigence aujourd'hui (en clair, explicite) — une régression qui viderait la slice
// serait détectée ici plutôt qu'au démarrage d'un des quatre binaires appelants. Voir ADR-036.
func TestDialOptionsSuffitPourConstruireUnClientGRPC(t *testing.T) {
	conn, err := grpc.NewClient("127.0.0.1:0", DialOptions()...)
	if err != nil {
		t.Fatalf("grpc.NewClient a échoué avec DialOptions() : %v", err)
	}
	defer conn.Close()
}

// Aujourd'hui, ServerOptions() n'ajoute aucun credential (gRPC en clair, ADR-036). Ce test fige
// ce fait : l'ajout silencieux d'une option ferait échouer ce test, obligeant à le mettre à jour
// consciemment plutôt que de laisser passer une modification du transport interne inaperçue.
func TestServerOptionsNAjouteAucunCredentialAujourdhui(t *testing.T) {
	opts := ServerOptions()
	if len(opts) != 0 {
		t.Fatalf("attendu aucune option de serveur aujourd'hui (gRPC en clair, ADR-036), obtenu %d", len(opts))
	}
}
