// Command audit-collector reçoit des événements d'audit bruts, les fait sceller par audit-sealer
// (socket Unix colocalisé — jamais un port réseau, voir contracts/proto/audit/v1/sealing.proto)
// et les persiste (schéma `audit`, rôle `audit_writer`). Câblage des producteurs
// (access-broker/admin-api/credential-issuer) différé, hors périmètre de ce lot.
//
// gRPC en clair côté serveur (AuditCollectionService, réseau normal) — même dette de TLS que
// partout ailleurs. Le lien vers audit-sealer, lui, n'est délibérément PAS du réseau ouvert : un
// socket Unix, seul moyen retenu de fermer l'oracle de signature sans mTLS/SPIFFE (absents du
// dépôt à ce jour).
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"

	"github.com/AlexisTak/biscuits-shield/apps/audit-collector/internal/collector"
	"github.com/AlexisTak/biscuits-shield/apps/audit-collector/internal/grpcapi"
	"github.com/AlexisTak/biscuits-shield/apps/audit-collector/internal/store"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "audit-collector: variable d'environnement manquante : %s\n", key)
		os.Exit(1)
	}
	return v
}

func main() {
	addr := envOr("ZS_AC_ADDR", "127.0.0.1:50065")
	sealerSocket := requireEnv("ZS_AC_AUDIT_SEALER_SOCKET")
	postgresDSN := requireEnv("ZS_AC_POSTGRES_DSN")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := store.Connect(ctx, postgresDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-collector: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	// "unix:" (pas "unix://") est le schéma reconnu par le résolveur gRPC natif pour un chemin de
	// socket local — audit-sealer n'est joignable que colocalisé sur le même hôte, jamais un
	// port réseau (voir sealing.proto).
	sealerConn, err := grpc.NewClient("unix:"+sealerSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-collector: connexion au socket audit-sealer %s : %v\n", sealerSocket, err)
		os.Exit(1)
	}
	defer sealerConn.Close()
	sealerClient := auditv1.NewAuditSealingServiceClient(sealerConn)

	col := collector.New(sealerClient, st)
	api := grpcapi.New(col)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-collector: liaison %s impossible : %v\n", addr, err)
		os.Exit(1)
	}

	server := grpc.NewServer()
	auditv1.RegisterAuditCollectionServiceServer(server, api)

	log.Printf("audit-collector: en écoute sur %s (audit-sealer via socket Unix %s — jamais un port réseau)", addr, sealerSocket)
	if err := server.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "audit-collector: erreur serveur : %v\n", err)
		os.Exit(1)
	}
}
