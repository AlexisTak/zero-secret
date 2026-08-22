// Command audit-collector reçoit, horodate, chaîne et signe le journal d'audit, et expose
// un journal vérifiable pour export SIEM. Non implémenté — voir backlog L1.4.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "audit-collector: non implémenté (backlog L1.4)")
	os.Exit(1)
}
