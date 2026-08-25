// Command access-broker orchestre le parcours JIT (L2.3) et l'expose en HTTP
// (contracts/openapi/access-broker.yaml). Premier binaire HTTP réel de ce composant — la
// logique vit dans internal/broker (bibliothèque testée sans réseau) et internal/httpapi
// (traduction HTTP <-> bibliothèque).
//
// gRPC en clair vers policy-engine/identity-provider — mTLS non câblé dans ce dépôt (aucune
// intégration SPIFFE/SPIRE), même limite que partout ailleurs (L2.2/H3/H4). Pas de TLS sur le
// serveur HTTP non plus — jamais un déploiement de production sans les deux.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	credentialv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/credential/v1"
	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"
	policyv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/policy/v1"

	"github.com/AlexisTak/biscuits-shield/apps/access-broker/internal/broker"
	"github.com/AlexisTak/biscuits-shield/apps/access-broker/internal/httpapi"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustDial(addr string) *grpc.ClientConn {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "access-broker: connexion à %s : %v\n", addr, err)
		os.Exit(1)
	}
	return conn
}

func main() {
	policyAddr := envOr("ZS_ACCESS_BROKER_POLICY_ENGINE_ADDR", "127.0.0.1:50061")
	identityAddr := envOr("ZS_ACCESS_BROKER_IDENTITY_PROVIDER_ADDR", "127.0.0.1:50062")
	credentialIssuerAddr := envOr("ZS_ACCESS_BROKER_CREDENTIAL_ISSUER_ADDR", "127.0.0.1:50064")
	auditCollectorAddr := envOr("ZS_ACCESS_BROKER_AUDIT_COLLECTOR_ADDR", "127.0.0.1:50065")
	httpAddr := envOr("ZS_ACCESS_BROKER_HTTP_ADDR", "127.0.0.1:8081")

	policyConn := mustDial(policyAddr)
	defer policyConn.Close()
	identityConn := mustDial(identityAddr)
	defer identityConn.Close()
	credentialConn := mustDial(credentialIssuerAddr)
	defer credentialConn.Close()
	auditConn := mustDial(auditCollectorAddr)
	defer auditConn.Close()

	policyClient := policyv1.NewPolicyDecisionServiceClient(policyConn)
	identityClient := identityv1.NewAssertionVerificationServiceClient(identityConn)
	credentialClient := credentialv1.NewCredentialIssuanceServiceClient(credentialConn)
	auditClient := auditv1.NewAuditCollectionServiceClient(auditConn)

	b := broker.New(policyClient, identityClient)
	api := httpapi.New(identityClient, credentialClient, auditClient, b)

	log.Printf("access-broker: en écoute sur %s (gRPC en clair vers %s, %s, %s, %s — mTLS hors périmètre)", httpAddr, policyAddr, identityAddr, credentialIssuerAddr, auditCollectorAddr)
	if err := http.ListenAndServe(httpAddr, httpapi.Handler(api)); err != nil {
		fmt.Fprintf(os.Stderr, "access-broker: erreur serveur HTTP : %v\n", err)
		os.Exit(1)
	}
}
