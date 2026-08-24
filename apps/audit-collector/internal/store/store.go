// Package store persiste les événements d'audit scellés (schéma `audit`, rôle `audit_writer`
// — SELECT+INSERT, jamais UPDATE/DELETE, migration 001). Premier driver Postgres du dépôt côté
// Go (`github.com/jackc/pgx/v5`, MIT) — mêmes garanties que `sqlx` côté Rust (paramètres liés
// systématiques, jamais de concaténation).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connexion audit_writer : %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("audit_writer indisponible : %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// ChainHead lit la tête de chaîne d'un domaine d'autorité — même requête que le pendant Rust
// (apps/identity-provider/src/store.rs::AuditStore::chain_head). Renvoie les octets scellés
// bruts de la tête, PAS un hash déjà calculé : aucun composant Go n'a le droit d'importer une
// bibliothèque de hachage directement (règle absolue #4, tools/lib/check-no-direct-crypto.sh
// interdit tout import crypto/* côté Go) — c'est à l'appelant (internal/collector) de faire
// hacher ces octets via AuditSealingService.HashPrevious, jamais localement.
type ChainHead struct {
	NextSequence    uint64
	PrevSealedBytes []byte // nil si aucun événement précédent (racine de chaîne)
}

func (s *Store) ChainHead(ctx context.Context, authorityDomain string) (ChainHead, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT sequence, sealed_bytes FROM audit.events
		 WHERE authority_domain = $1 ORDER BY sequence DESC LIMIT 1`,
		authorityDomain,
	)
	var sequence int64
	var sealedBytes []byte
	err := row.Scan(&sequence, &sealedBytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ChainHead{NextSequence: 0, PrevSealedBytes: nil}, nil
		}
		return ChainHead{}, fmt.Errorf("lecture de la tête de chaîne : %w", err)
	}
	return ChainHead{
		NextSequence:    uint64(sequence) + 1,
		PrevSealedBytes: sealedBytes,
	}, nil
}

// AppendInput porte tout ce qui doit être persisté — les octets scellés (`sealed_bytes`) sont la
// preuve, les colonnes décomposées (actor/target/outcome/context) ne servent qu'à
// l'interrogation, jamais à la vérification (même principe que côté Rust).
type AppendInput struct {
	EventID         string
	Sequence        uint64
	OccurredAt      string // RFC 3339, déjà formaté par l'appelant
	AuthorityDomain string
	EventType       string
	ActorJSON       []byte
	TargetJSON      []byte // nil si absent
	Outcome         string
	ContextJSON     []byte // nil si absent
	PrevHashHex     string
	SignatureJSON   []byte
	SealedBytes     []byte
}

// Append ajoute un événement déjà scellé — atomique via la contrainte d'unicité
// `(authority_domain, sequence)` (migration 002) : un conflit de concurrence remonte comme une
// erreur Postgres ordinaire, jamais ré-essayé silencieusement avec une nouvelle séquence
// (seal() n'est pas idempotent côté audit-sealer, ADR-011 — un ré-essai produirait une seconde
// signature valide sur le même (sequence, prev_hash), risque de fourche).
func (s *Store) Append(ctx context.Context, in AppendInput) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit.events
		 (event_id, sequence, occurred_at, authority_domain, event_type, actor, target, outcome,
		  context, prev_hash, signature, sealed_bytes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		in.EventID, int64(in.Sequence), in.OccurredAt, in.AuthorityDomain, in.EventType,
		in.ActorJSON, nullableJSON(in.TargetJSON), in.Outcome, nullableJSON(in.ContextJSON),
		in.PrevHashHex, in.SignatureJSON, in.SealedBytes,
	)
	if err != nil {
		return fmt.Errorf("ajout à la chaîne : %w", err)
	}
	return nil
}

func nullableJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}
