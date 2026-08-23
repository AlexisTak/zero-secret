package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIssueLeaseReussitContreUnServeurOpenBaoSimule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("méthode inattendue : %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease_id":       "database/creds/readonly/abc123",
			"lease_duration": 900,
			"renewable":      true,
			"data": map[string]any{
				"username": "v-readonly-abc",
				"password": "un-secret-tres-sensible",
			},
		})
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "jeton-de-test"})
	if err != nil {
		t.Fatalf("construction du client : %v", err)
	}

	lease, err := client.IssueLease(context.Background(), "database/creds/readonly", nil)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if lease.ID != "database/creds/readonly/abc123" {
		t.Fatalf("ID de bail inattendu : %s", lease.ID)
	}
	if lease.LeaseDuration != 900*time.Second {
		t.Fatalf("durée de bail inattendue : %s", lease.LeaseDuration)
	}
	if !lease.Renewable {
		t.Fatal("attendu renouvelable")
	}
	if lease.Data["password"] != "un-secret-tres-sensible" {
		t.Fatal("les données du bail n'ont pas été transmises")
	}
}

func TestIndisponibiliteEstUnRefusExpliciteJamaisUnRepli(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "jeton-de-test"})
	if err != nil {
		t.Fatalf("construction du client : %v", err)
	}

	lease, err := client.IssueLease(context.Background(), "database/creds/readonly", nil)
	if err == nil {
		t.Fatal("attendu une erreur")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attendu ErrUnavailable, reçu : %v", err)
	}
	if lease.ID != "" {
		t.Fatal("aucun bail partiel ne doit être retourné")
	}
}

func TestReponseSansBailExploitableEstUnRefus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "jeton-de-test"})
	if err != nil {
		t.Fatalf("construction du client : %v", err)
	}

	_, err = client.IssueLease(context.Background(), "database/creds/readonly", nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attendu ErrUnavailable pour une réponse sans lease_id, reçu : %v", err)
	}
}

func TestDepassementDeDelaiEstUnRefusExplicite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "jeton-de-test", Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("construction du client : %v", err)
	}

	start := time.Now()
	_, err = client.IssueLease(context.Background(), "database/creds/readonly", nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attendu ErrUnavailable au dépassement de délai, reçu : %v", err)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("le timeout n'a pas été respecté, appel resté bloqué %s", elapsed)
	}
}

func TestRevokeReussitEtRefuseSurIndisponibilite(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "jeton-de-test"})
	if err != nil {
		t.Fatalf("construction du client : %v", err)
	}

	if err := client.Revoke(context.Background(), "database/creds/readonly/abc123"); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !strings.Contains(received, "sys/leases/revoke") {
		t.Fatalf("chemin de révocation inattendu : %s", received)
	}

	srv.Close() // serveur fermé : l'appel suivant doit échouer explicitement.
	if err := client.Revoke(context.Background(), "database/creds/readonly/abc123"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attendu ErrUnavailable, reçu : %v", err)
	}
}

func TestLeaseStringNeFuiteJamaisLeSecret(t *testing.T) {
	lease := Lease{
		ID: "database/creds/readonly/abc123",
		Data: map[string]any{
			"username": "v-readonly-abc",
			"password": "un-secret-tres-sensible-a-ne-jamais-logger",
		},
		LeaseDuration: 900 * time.Second,
		Renewable:     true,
	}

	s := lease.String()
	if strings.Contains(s, "un-secret-tres-sensible-a-ne-jamais-logger") {
		t.Fatalf("String() a fait fuiter le secret : %s", s)
	}
	gs := lease.GoString()
	if strings.Contains(gs, "un-secret-tres-sensible-a-ne-jamais-logger") {
		t.Fatalf("GoString() a fait fuiter le secret : %s", gs)
	}
	// %v et %+v passent par String() pour un type qui l'implémente — vérifié explicitement,
	// pas supposé.
	if got := fmt.Sprintf("%+v", lease); strings.Contains(got, "un-secret-tres-sensible-a-ne-jamais-logger") {
		t.Fatalf("le formatage %%+v a fait fuiter le secret : %s", got)
	}
}
