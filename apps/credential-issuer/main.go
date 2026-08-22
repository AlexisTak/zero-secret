// Command credential-issuer est le seul composant autorisé à dialoguer avec OpenBao et le HSM.
// Non implémenté — voir backlog L2+.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "credential-issuer: non implémenté (backlog L2+)")
	os.Exit(1)
}
