// Command admin-api gère l'administration des politiques, identités et approbations.
// Quorum requis sur les opérations critiques. Non implémenté — voir backlog L2+.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "admin-api: non implémenté (backlog L2+)")
	os.Exit(1)
}
