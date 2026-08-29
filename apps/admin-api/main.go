// Command admin-api expose le quorum sur les opérations critiques en HTTP (L2.5, ADR-021,
// contracts/openapi/admin-api.yaml). Premier binaire HTTP réel de ce composant — logique dans
// internal/quorum (bibliothèque testée sans réseau), traduction HTTP dans internal/httpapi.
//
// Portée réduite assumée (ADR-021) : ce binaire ne gère ni politique ni identité, seulement la
// vérification de quorum. gRPC en clair vers identity-provider, pas de TLS sur le serveur HTTP —
// mêmes limites que partout ailleurs dans ce lot.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/httpapi"
	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	identityAddr := envOr("ZS_ADMIN_API_IDENTITY_PROVIDER_ADDR", "127.0.0.1:50062")
	auditCollectorAddr := envOr("ZS_ADMIN_API_AUDIT_COLLECTOR_ADDR", "127.0.0.1:50065")
	httpAddr := envOr("ZS_ADMIN_API_HTTP_ADDR", "127.0.0.1:8082")
	// Domaine d'autorite contre lequel toute assertion est verifiee — fixe par la configuration,
	// jamais propose par la requete (ADR-035). Obligatoire et sans valeur par defaut : un ancrage
	// de confiance qui se replie silencieusement sur une valeur generique n'ancre rien, et un
	// deploiement qui oublie la variable demarrerait en croyant le controle actif.
	expectedAuthorityDomain := os.Getenv("ZS_ADMIN_API_EXPECTED_AUTHORITY_DOMAIN")
	if expectedAuthorityDomain == "" {
		fmt.Fprintln(os.Stderr, "admin-api: ZS_ADMIN_API_EXPECTED_AUTHORITY_DOMAIN est obligatoire (domaine d'autorité attendu des assertions)")
		os.Exit(1)
	}

	identityConn, err := grpc.NewClient(identityAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin-api: connexion à %s : %v\n", identityAddr, err)
		os.Exit(1)
	}
	defer identityConn.Close()

	auditConn, err := grpc.NewClient(auditCollectorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin-api: connexion à %s : %v\n", auditCollectorAddr, err)
		os.Exit(1)
	}
	defer auditConn.Close()

	identityClient := identityv1.NewAssertionVerificationServiceClient(identityConn)
	auditClient := auditv1.NewAuditCollectionServiceClient(auditConn)
	verifier := quorum.New(identityClient)
	api := httpapi.New(verifier, identityClient, auditClient, expectedAuthorityDomain)

	log.Printf("admin-api: en écoute sur %s (gRPC en clair vers %s, %s — mTLS hors périmètre)", httpAddr, identityAddr, auditCollectorAddr)
	if err := http.ListenAndServe(httpAddr, httpapi.NewHandler(api)); err != nil {
		fmt.Fprintf(os.Stderr, "admin-api: erreur serveur HTTP : %v\n", err)
		os.Exit(1)
	}
}
