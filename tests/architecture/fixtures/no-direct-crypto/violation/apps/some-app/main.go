// Violation : import crypto direct (stdlib) hors zs-crypto.
package main

import (
	"crypto/ed25519"
	"fmt"
)

func main() {
	_, priv, _ := ed25519.GenerateKey(nil)
	fmt.Println(len(priv))
}
