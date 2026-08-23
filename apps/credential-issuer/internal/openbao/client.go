// Package openbao est l'interface unique de credential-issuer vers OpenBao (ADR-002 : « aucun
// autre composant ne connaît son adresse ni ne détient de jeton pour lui »). H2 livre le client
// générique de bail — quel moteur de secrets pour quel verbe (PostgreSQL dynamique, PKI, KV) est
// une décision de L2.4, pas de H2 (voir ADR-018).
//
// Bibliothèque cliente : github.com/openbao/openbao/api/v2 (MPL-2.0, module publié et versionné)
// — pas github.com/hashicorp/vault/api (BUSL-1.1) : ADR-002 a choisi OpenBao précisément pour sa
// licence OSI, importer le client Vault contredirait la raison même de ce choix.
package openbao

import (
	"context"
	"errors"
	"fmt"
	"time"

	openbaoapi "github.com/openbao/openbao/api/v2"
)

// DefaultTimeout borne chaque appel sortant vers OpenBao — convention Go du CLAUDE.md racine
// (« timeout explicite sur tout appel sortant »). Dépassement = refus explicite (ErrUnavailable),
// jamais un blocage indéfini.
const DefaultTimeout = 5 * time.Second

// ErrUnavailable est retournée pour toute indisponibilité d'OpenBao (réseau, 5xx, timeout) —
// jamais un repli sur un credential généré localement ou un succès partiel (R2, critère
// d'acceptation explicite du backlog H2).
var ErrUnavailable = errors.New("openbao indisponible")

// Client est l'unique point d'accès à OpenBao. Non exporté hors de ce paquet applicatif
// (`internal/`) : rien d'autre que credential-issuer ne doit pouvoir l'importer (ADR-002).
type Client struct {
	inner   *openbaoapi.Client
	timeout time.Duration
}

// Config configure la connexion. Token est fourni par l'appelant (variable d'environnement
// ZS_CI_OPENBAO_TOKEN côté main.go) — authentification par jeton provisoire et signalée (ADR-018)
// : en dev, OpenBao génère son propre jeton root, jamais fixé en dur (règle absolue #1). Un
// mécanisme d'authentification de production (AppRole, Kubernetes auth) n'est pas conçu ici.
type Config struct {
	Address string
	Token   string
	Timeout time.Duration // zéro => DefaultTimeout
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("openbao: adresse manquante")
	}
	if cfg.Token == "" {
		return nil, errors.New("openbao: jeton manquant")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	baoConfig := openbaoapi.DefaultConfig()
	baoConfig.Address = cfg.Address
	baoConfig.Timeout = timeout
	// Retries désactivés explicitement : un retry automatique masquerait une indisponibilité
	// réelle derrière un délai variable, rendant le comportement de refus moins prévisible et
	// plus difficile à tester. Une politique de retry authentique reste à instruire (ADR-018).
	baoConfig.MaxRetries = 0

	inner, err := openbaoapi.NewClient(baoConfig)
	if err != nil {
		return nil, fmt.Errorf("openbao: construction du client : %w", err)
	}
	inner.SetToken(cfg.Token)

	return &Client{inner: inner, timeout: timeout}, nil
}

// Lease est un bail émis par OpenBao. String()/GoString() masquent Data — un log accidentel
// (%v, %+v) ne doit jamais faire fuiter un secret (règle absolue #1).
type Lease struct {
	ID            string
	Data          map[string]any
	LeaseDuration time.Duration
	Renewable     bool
}

func (l Lease) String() string {
	return fmt.Sprintf("Lease{ID: %s, LeaseDuration: %s, Renewable: %t, Data: [%d clé(s) masquée(s)]}",
		l.ID, l.LeaseDuration, l.Renewable, len(l.Data))
}

func (l Lease) GoString() string {
	return l.String()
}

// IssueLease écrit à path avec params et retourne le bail émis. Indisponibilité, timeout ou
// réponse sans lease_id : ErrUnavailable, jamais un bail partiel.
func (c *Client) IssueLease(ctx context.Context, path string, params map[string]any) (Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	secret, err := c.inner.Logical().WriteWithContext(ctx, path, params)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: écriture %s : %v", ErrUnavailable, path, err)
	}
	if secret == nil || secret.LeaseID == "" {
		return Lease{}, fmt.Errorf("%w: réponse sans bail exploitable pour %s", ErrUnavailable, path)
	}

	return Lease{
		ID:            secret.LeaseID,
		Data:          secret.Data,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		Renewable:     secret.Renewable,
	}, nil
}

// Revoke révoque un bail. Indisponibilité ou erreur OpenBao : ErrUnavailable — jamais un succès
// silencieux sur une révocation qui n'a pas réellement eu lieu.
func (c *Client) Revoke(ctx context.Context, leaseID string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if err := c.inner.Sys().RevokeWithContext(ctx, leaseID); err != nil {
		return fmt.Errorf("%w: révocation %s : %v", ErrUnavailable, leaseID, err)
	}
	return nil
}
