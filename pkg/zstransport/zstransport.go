// Package zstransport centralise la construction des serveurs et clients gRPC internes
// (access-broker, admin-api, audit-collector, credential-issuer).
//
// État actuel (ADR-001, ADR-036) : gRPC en clair, aucune identité de workload vérifiée.
// mTLS/SPIFFE-SPIRE est PLANNED, non implémenté dans ce dépôt. Ce paquet est le seul point
// d'insertion prévu pour les credentials de transport interne : quand la migration sera
// acceptée, seules ces deux fonctions changent, pas chacun des appelants (aujourd'hui dispersés
// dans main.go de quatre binaires).
//
// Ce paquet ne fait la moindre tentative de TLS conditionnel ou partiel : une configuration TLS
// mal câblée qui se ferait passer pour de la mTLS serait pire que l'absence actuelle, explicite
// et documentée (règle absolue #2 du CLAUDE.md — refus par défaut, jamais de sécurité simulée).
package zstransport

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ServerOptions retourne les options de transport pour un serveur gRPC interne.
//
// Aujourd'hui : aucune option de credentials (gRPC en clair). Voir ADR-036 pour la trajectoire
// de migration vers mTLS/SPIFFE-SPIRE.
func ServerOptions() []grpc.ServerOption {
	return nil
}

// DialOptions retourne les options de transport pour un client gRPC interne.
//
// Aujourd'hui : credentials explicitement non chiffrées (insecure.NewCredentials()) — un choix
// audité et documenté au sens de ADR-001/ADR-036, pas un défaut implicite silencieux.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}
