// Command credential-issuer est le seul composant autorisé à dialoguer avec OpenBao et le HSM
// (ADR-002). Premier binaire réseau réel de ce composant (backlog L2.4, suite) — la logique vit
// dans internal/issuer (bibliothèque testée sans réseau) et internal/openbao (client H2) ;
// internal/grpcapi ne fait que traduire.
//
// gRPC en clair vers policy-engine — mTLS non câblé dans ce dépôt (aucune intégration
// SPIFFE/SPIRE), même limite que partout ailleurs. Pas de TLS sur le serveur gRPC non plus.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	credentialv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/credential/v1"
	policyv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/policy/v1"

	"github.com/AlexisTak/biscuits-shield/apps/credential-issuer/internal/grpcapi"
	"github.com/AlexisTak/biscuits-shield/apps/credential-issuer/internal/issuer"
	"github.com/AlexisTak/biscuits-shield/apps/credential-issuer/internal/openbao"
)

// leaseIssuerAdapter satisfait issuer.LeaseIssuer en enveloppant *openbao.Client — les deux
// paquets internes ne s'importent pas l'un l'autre (issuer.go l'explique : évite un couplage
// circulaire), donc la conversion openbao.Lease -> issuer.Lease vit ici, au point d'assemblage,
// pas dans l'un ou l'autre paquet.
type leaseIssuerAdapter struct {
	client *openbao.Client
}

func (a leaseIssuerAdapter) IssueLease(ctx context.Context, path string, params map[string]any) (issuer.Lease, error) {
	lease, err := a.client.IssueLease(ctx, path, params)
	if err != nil {
		return issuer.Lease{}, err
	}
	return issuer.Lease{ID: lease.ID, LeaseDuration: lease.LeaseDuration}, nil
}

func (a leaseIssuerAdapter) Revoke(ctx context.Context, leaseID string) error {
	return a.client.Revoke(ctx, leaseID)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "credential-issuer: variable d'environnement manquante : %s\n", key)
		os.Exit(1)
	}
	return v
}

func main() {
	addr := envOr("ZS_CI_ADDR", "127.0.0.1:50064")
	policyEngineAddr := envOr("ZS_CI_POLICY_ENGINE_ADDR", "127.0.0.1:50061")
	auditCollectorAddr := envOr("ZS_CI_AUDIT_COLLECTOR_ADDR", "127.0.0.1:50065")
	openBaoAddr := requireEnv("ZS_CI_OPENBAO_ADDR")
	// Jeton provisoire, signalé (ADR-018) — jamais fixé en dur (règle absolue #1).
	openBaoToken := requireEnv("ZS_CI_OPENBAO_TOKEN")

	policyConn, err := grpc.NewClient(policyEngineAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential-issuer: connexion à %s : %v\n", policyEngineAddr, err)
		os.Exit(1)
	}
	defer policyConn.Close()
	policyClient := policyv1.NewPolicyDecisionServiceClient(policyConn)

	auditConn, err := grpc.NewClient(auditCollectorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential-issuer: connexion à %s : %v\n", auditCollectorAddr, err)
		os.Exit(1)
	}
	defer auditConn.Close()
	auditClient := auditv1.NewAuditCollectionServiceClient(auditConn)

	openBaoClient, err := openbao.NewClient(openbao.Config{Address: openBaoAddr, Token: openBaoToken})
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential-issuer: échec de la connexion OpenBao : %v\n", err)
		os.Exit(1)
	}

	iss := issuer.New(policyClient, leaseIssuerAdapter{client: openBaoClient}, issuer.NewInMemoryConsumedDecisionStore())
	api := grpcapi.New(iss, auditClient)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential-issuer: liaison %s impossible : %v\n", addr, err)
		os.Exit(1)
	}

	server := grpc.NewServer()
	credentialv1.RegisterCredentialIssuanceServiceServer(server, api)

	log.Printf("credential-issuer: en écoute sur %s (gRPC en clair vers %s, %s — mTLS hors périmètre)", addr, policyEngineAddr, auditCollectorAddr)
	if err := server.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "credential-issuer: erreur serveur : %v\n", err)
		os.Exit(1)
	}
}
