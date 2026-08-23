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

	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/admin-api/internal/httpapi"
	"github.com/Biscuits-ia/biscuits-shield/apps/admin-api/internal/quorum"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	identityAddr := envOr("ZS_ADMIN_API_IDENTITY_PROVIDER_ADDR", "127.0.0.1:50062")
	httpAddr := envOr("ZS_ADMIN_API_HTTP_ADDR", "127.0.0.1:8082")

	identityConn, err := grpc.NewClient(identityAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin-api: connexion à %s : %v\n", identityAddr, err)
		os.Exit(1)
	}
	defer identityConn.Close()

	identityClient := identityv1.NewAssertionVerificationServiceClient(identityConn)
	verifier := quorum.New(identityClient)
	api := httpapi.New(verifier)

	log.Printf("admin-api: en écoute sur %s (gRPC en clair vers %s — mTLS hors périmètre)", httpAddr, identityAddr)
	if err := http.ListenAndServe(httpAddr, httpapi.Handler(api)); err != nil {
		fmt.Fprintf(os.Stderr, "admin-api: erreur serveur HTTP : %v\n", err)
		os.Exit(1)
	}
}
