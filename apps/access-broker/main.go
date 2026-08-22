// Command access-broker orchestre le parcours JIT : motif, approbation, appel PDP,
// déclenchement d'émission, expiration, révocation. Non implémenté — voir backlog L2+.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "access-broker: non implémenté (backlog L2+)")
	os.Exit(1)
}
