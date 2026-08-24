package issuer

import "sync"

// InMemoryConsumedDecisionStore implémente ConsumedDecisionStore — mono-instance, en mémoire,
// même famille de coupe de portée que apps/console-web/src/session.go (Map + mutex, pas de
// magasin partagé). Contrairement à une session qui expire, une décision consommée n'est
// jamais retirée de la carte : la revoir une seconde fois doit toujours échouer, même après
// l'expiration de son max_ttl (une décision expirée mais déjà rejouée reste une tentative de
// rejeu, pas un cas légitime). Le coût mémoire est borné par le volume de décisions ALLOW
// réellement émises, pas par le trafic de vérification.
type InMemoryConsumedDecisionStore struct {
	mu       sync.Mutex
	consumed map[string]struct{}
}

func NewInMemoryConsumedDecisionStore() *InMemoryConsumedDecisionStore {
	return &InMemoryConsumedDecisionStore{consumed: make(map[string]struct{})}
}

// MarkConsumed est atomique par construction : la section critique couvre la lecture ET
// l'écriture, deux appels concurrents avec le même decisionHash ne peuvent jamais réussir tous
// les deux (contrat exigé par ConsumedDecisionStore, mise en garde sur la fenêtre TOCTOU d'un
// get-puis-set séparé).
func (s *InMemoryConsumedDecisionStore) MarkConsumed(decisionHash []byte) (bool, error) {
	key := string(decisionHash)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.consumed[key]; ok {
		return true, nil
	}
	s.consumed[key] = struct{}{}
	return false, nil
}
