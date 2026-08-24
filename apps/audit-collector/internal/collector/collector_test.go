package collector

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/audit-collector/internal/store"
)

// Doublures locales — même patron que credential-issuer/internal/grpcapi (aucune crypto
// fabriquée côté Go, audit-sealer est le seul appelé pour de vrai en intégration).

type fakeSealer struct {
	auditv1.AuditSealingServiceClient
	sealCalls   int
	sealErr     error
	sealedOut   []byte
	hashOut     []byte
	lastSealReq *auditv1.SealRequest
}

func (f *fakeSealer) Seal(ctx context.Context, in *auditv1.SealRequest, opts ...grpc.CallOption) (*auditv1.SealResponse, error) {
	f.sealCalls++
	f.lastSealReq = in
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return &auditv1.SealResponse{SealedBytes: f.sealedOut}, nil
}

func (f *fakeSealer) HashPrevious(ctx context.Context, in *auditv1.HashPreviousRequest, opts ...grpc.CallOption) (*auditv1.HashPreviousResponse, error) {
	return &auditv1.HashPreviousResponse{Digest: f.hashOut}, nil
}

type fakeStore struct {
	head       store.ChainHead
	headErr    error
	appendErr  error
	appendedIn *store.AppendInput
}

func (f *fakeStore) ChainHead(ctx context.Context, authorityDomain string) (store.ChainHead, error) {
	return f.head, f.headErr
}

func (f *fakeStore) Append(ctx context.Context, in store.AppendInput) error {
	if f.appendErr != nil {
		return f.appendErr
	}
	in2 := in
	f.appendedIn = &in2
	return nil
}

func validRawEvent() *auditv1.RawEvent {
	return &auditv1.RawEvent{
		AuthorityDomain: "corp.eu-west",
		EventType:       "authentication.succeeded",
		Actor:           &auditv1.Actor{SubjectId: "alice", Kind: "human"},
		Outcome:         "success",
	}
}

func TestFluxNominalScelleEtPersisteAvecUneNouvelleSequence(t *testing.T) {
	sealer := &fakeSealer{sealedOut: []byte("octets-scelles")}
	st := &fakeStore{head: store.ChainHead{NextSequence: 0, PrevSealedBytes: nil}}
	c := New(sealer, st)

	result, err := c.Record(context.Background(), validRawEvent())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !result.Accepted {
		t.Fatalf("attendu accepté, raison : %s", result.Reason)
	}
	if result.Sequence != 0 {
		t.Fatalf("séquence inattendue : %d", result.Sequence)
	}
	if result.EventID == "" {
		t.Fatal("event_id attendu, généré par le collecteur")
	}
	if st.appendedIn == nil {
		t.Fatal("Append aurait dû être appelé")
	}
	if !bytes.Equal(st.appendedIn.SealedBytes, []byte("octets-scelles")) {
		t.Fatalf("sealed_bytes inattendus : %s", st.appendedIn.SealedBytes)
	}
	// Racine de chaîne (32 octets nuls, encodés hex) attendue pour le premier événement d'un
	// domaine — même convention que zs_audit::CHAIN_ROOT.
	wantPrevHash := hex.EncodeToString(chainRoot)
	if st.appendedIn.PrevHashHex != wantPrevHash {
		t.Fatalf("prev_hash inattendu : %s", st.appendedIn.PrevHashHex)
	}
}

func TestUnEvenementPrecedentFaitHacherSesOctetsScellesPourLePrevHash(t *testing.T) {
	sealer := &fakeSealer{sealedOut: []byte("nouveaux-octets"), hashOut: bytes.Repeat([]byte{0xAB}, 32)}
	st := &fakeStore{head: store.ChainHead{NextSequence: 5, PrevSealedBytes: []byte("octets-precedents")}}
	c := New(sealer, st)

	result, err := c.Record(context.Background(), validRawEvent())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Sequence != 5 {
		t.Fatalf("séquence inattendue : %d", result.Sequence)
	}
	wantHex := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	if st.appendedIn.PrevHashHex != wantHex {
		t.Fatalf("prev_hash inattendu : %s", st.appendedIn.PrevHashHex)
	}
}

func TestEventTypeInconnuEstRefuseSansErreurDeTransport(t *testing.T) {
	sealer := &fakeSealer{sealErr: status.Error(codes.InvalidArgument, "event_type_inconnu_ou_non_supporte")}
	st := &fakeStore{}
	c := New(sealer, st)

	result, err := c.Record(context.Background(), validRawEvent())
	if err != nil {
		t.Fatalf("un refus métier ne doit jamais être une erreur Go : %v", err)
	}
	if result.Accepted {
		t.Fatal("attendu refusé")
	}
	if result.Reason == "" {
		t.Fatal("une raison de refus est attendue")
	}
	if st.appendedIn != nil {
		t.Fatal("un événement refusé par audit-sealer ne doit jamais être persisté")
	}
}

func TestPanneDuScelleurEstUneErreurDeTransport(t *testing.T) {
	sealer := &fakeSealer{sealErr: status.Error(codes.Unavailable, "hsm indisponible")}
	st := &fakeStore{}
	c := New(sealer, st)

	_, err := c.Record(context.Background(), validRawEvent())
	if err == nil {
		t.Fatal("une panne de transport doit remonter comme une erreur Go, pas un refus silencieux")
	}
}

func TestConflitDeSequenceNestJamaisReessaye(t *testing.T) {
	sealer := &fakeSealer{sealedOut: []byte("octets")}
	st := &fakeStore{
		head:      store.ChainHead{NextSequence: 3},
		appendErr: errors.New(`duplicate key value violates unique constraint "events_authority_domain_sequence_key"`),
	}
	c := New(sealer, st)

	_, err := c.Record(context.Background(), validRawEvent())
	if err == nil {
		t.Fatal("un conflit de séquence doit remonter comme une erreur, jamais un succès silencieux")
	}
	if sealer.sealCalls != 1 {
		t.Fatalf("seal() n'est pas idempotent (ADR-011) — attendu exactement 1 appel, obtenu %d : un ré-essai produirait une seconde signature valide sur le même (sequence, prev_hash)", sealer.sealCalls)
	}
}

func TestChampsOptionnelsAbsentsNeSontJamaisSerialisesEnNull(t *testing.T) {
	sealer := &fakeSealer{sealedOut: []byte("octets")}
	st := &fakeStore{}
	c := New(sealer, st)

	raw := validRawEvent()
	raw.Target = nil
	raw.Context = nil

	if _, err := c.Record(context.Background(), raw); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if st.appendedIn.TargetJSON != nil {
		t.Fatalf("target absent doit rester nil, obtenu : %s", st.appendedIn.TargetJSON)
	}
	if st.appendedIn.ContextJSON != nil {
		t.Fatalf("context absent doit rester nil, obtenu : %s", st.appendedIn.ContextJSON)
	}
}

func TestActeurEstSerialiseAvecLesNomsDeChampsDuContrat(t *testing.T) {
	sealer := &fakeSealer{sealedOut: []byte("octets")}
	st := &fakeStore{}
	c := New(sealer, st)

	raw := validRawEvent()
	if _, err := c.Record(context.Background(), raw); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	// contracts/events/audit-event.schema.json exige subject_id/kind en snake_case.
	if !bytes.Contains(st.appendedIn.ActorJSON, []byte(`"subject_id"`)) {
		t.Fatalf("subject_id attendu en snake_case, obtenu : %s", st.appendedIn.ActorJSON)
	}
}

func TestDecisionEstTransmiseAAuditSealer(t *testing.T) {
	// Régression : Record() construisait le SealRequest sans jamais lire raw.GetDecision(),
	// donc tout policy.decided était silencieusement rejeté par audit-sealer (couplage
	// decision<->event_type violé, ADR-027) sans qu'aucune erreur Go ne remonte — le refus
	// métier devient un Result{Accepted:false}, jamais vérifié par les appelants best-effort
	// (access-broker). Ce test échoue si le champ decision cesse d'être transmis.
	sealer := &fakeSealer{sealedOut: []byte("octets")}
	st := &fakeStore{}
	c := New(sealer, st)

	raw := &auditv1.RawEvent{
		AuthorityDomain: "corp.eu-west",
		EventType:       "policy.decided",
		Actor:           &auditv1.Actor{SubjectId: "alice", Kind: "human"},
		Outcome:         "success",
		Decision: &auditv1.Decision{
			RequestId:     "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			DecisionHash:  []byte{0xCD, 0xCD},
			PolicyVersion: "db.connect@1",
			Reasons:       []string{"db-connect-production"},
		},
	}
	if _, err := c.Record(context.Background(), raw); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if sealer.lastSealReq.Decision == nil {
		t.Fatal("decision aurait dû être transmise dans le SealRequest envoyé à audit-sealer")
	}
	if sealer.lastSealReq.Decision.RequestId != "f47ac10b-58cc-4372-a567-0e02b2c3d479" {
		t.Fatalf("decision.request_id inattendu : %s", sealer.lastSealReq.Decision.RequestId)
	}
}
