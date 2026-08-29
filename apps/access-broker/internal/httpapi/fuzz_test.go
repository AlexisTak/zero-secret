package httpapi

import (
	"encoding/json"
	"testing"
)

// FuzzSecurityDecodeAccessRequestBody — cible de `make security-fuzz`.
func FuzzSecurityDecodeAccessRequestBody(f *testing.F) {
	f.Add([]byte(`{"verb":"db.connect","resource":{"type":"Database","id":"x","authority_domain":"x"},"expected_authority_domain":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"resource":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var body AccessRequestBody
		_ = json.Unmarshal(data, &body)
	})
}
