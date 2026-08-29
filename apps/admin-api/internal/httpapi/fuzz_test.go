package httpapi

import (
	"encoding/json"
	"testing"
)

// FuzzSecurityDecodeQuorumRequest fuzze le décodeur JSON de QuorumRequest — cible de
// `make security-fuzz` (go test -fuzz=FuzzSecurityDecodeQuorumRequest -fuzztime=60s). Sans le
// flag -fuzz, ce test exécute uniquement le corpus de départ (seed) — inclus dans
// `make security-quick` à coût nul.
func FuzzSecurityDecodeQuorumRequest(f *testing.F) {
	f.Add([]byte(`{"assertions":["YQ=="],"threshold":2,"expected_authority_domain":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"threshold":-1}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"assertions":[123]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var req QuorumRequest
		// Ne doit jamais paniquer, quel que soit le contenu — un décodage invalide renvoie une
		// erreur, jamais un crash du processus.
		_ = json.Unmarshal(data, &req)
	})
}
