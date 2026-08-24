package grpcapi

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/audit-collector/internal/collector"
	"github.com/Biscuits-ia/biscuits-shield/apps/audit-collector/internal/store"
)

// Doublures locales — même patron que credential-issuer/internal/grpcapi.

type fakeSealer struct {
	auditv1.AuditSealingServiceClient
}

func (f *fakeSealer) Seal(ctx context.Context, in *auditv1.SealRequest, opts ...grpc.CallOption) (*auditv1.SealResponse, error) {
	return &auditv1.SealResponse{SealedBytes: []byte("octets-scelles")}, nil
}

func (f *fakeSealer) HashPrevious(ctx context.Context, in *auditv1.HashPreviousRequest, opts ...grpc.CallOption) (*auditv1.HashPreviousResponse, error) {
	return &auditv1.HashPreviousResponse{Digest: make([]byte, 32)}, nil
}

type fakeStore struct{}

func (f *fakeStore) ChainHead(ctx context.Context, authorityDomain string) (store.ChainHead, error) {
	return store.ChainHead{NextSequence: 0}, nil
}

func (f *fakeStore) Append(ctx context.Context, in store.AppendInput) error {
	return nil
}

// startServer démarre un vrai serveur gRPC sur un port éphémère et retourne un client réel
// connecté dessus — round-trip réseau réel, seule la dépendance en aval (audit-sealer) est
// doublée (même patron que credential-issuer/internal/grpcapi).
func startServer(t *testing.T, c *collector.Collector) auditv1.AuditCollectionServiceClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("liaison : %v", err)
	}
	server := grpc.NewServer()
	auditv1.RegisterAuditCollectionServiceServer(server, New(c))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("connexion client : %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return auditv1.NewAuditCollectionServiceClient(conn)
}

func TestRecordAccepteViaLeReseauRetourneLaSequence(t *testing.T) {
	c := collector.New(&fakeSealer{}, &fakeStore{})
	client := startServer(t, c)

	resp, err := client.Record(context.Background(), &auditv1.RawEvent{
		AuthorityDomain: "corp.eu-west",
		EventType:       "authentication.succeeded",
		Actor:           &auditv1.Actor{SubjectId: "alice", Kind: "human"},
		Outcome:         "success",
	})
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("attendu accepté, raison : %s", resp.Reason)
	}
	if resp.EventId == "" {
		t.Fatal("event_id attendu")
	}
}
