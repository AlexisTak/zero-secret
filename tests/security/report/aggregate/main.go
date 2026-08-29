// Package main lit les rapports JSON écrits par chaque module de test de sécurité
// (tests/security/report/output/*.json) et produit un résumé Markdown sur stdout. N'importe
// aucun package internal/ d'app — seul le format JSON documenté dans tests/security/README.md
// est un contrat entre ce binaire et les modules qui écrivent les rapports.
//
// Code de sortie : 0 si aucun finding bloquant, 1 si au moins un finding porte blocking=true,
// 2 en cas d'usage incorrect. C'est ce binaire — et non un grep sur la mise en forme du JSON —
// qui porte la decision bloquante de la cible make security-quick : le champ Blocking est deja
// desserialise ici, le lire est le seul controle qui ne se casse pas silencieusement si
// l'indentation du rapport change.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Expected    string   `json:"expected"`
	Obtained    string   `json:"obtained"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	OWASP       []string `json:"owasp"`
	CWE         string   `json:"cwe"`
	Blocking    bool     `json:"blocking"`
}

var severityRank = map[string]int{
	"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

// rank renvoie le rang de tri d'une sévérité — une valeur non reconnue (fichier de rapport
// malformé) est triée après INFO, jamais confondue avec CRITICAL (zero value de la map).
func rank(severity string) int {
	if r, ok := severityRank[severity]; ok {
		return r
	}
	return len(severityRank)
}

func main() {
	os.Exit(run())
}

// run renvoie le code de sortie du binaire — separe de main pour rester testable.
func run() int {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aggregate <dossier-output>")
		return 2
	}
	dir := os.Args[1]

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregate: lecture de %s : %v\n", dir, err)
		os.Exit(1)
	}

	var all []finding
	parsedFiles := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aggregate: lecture de %s : %v\n", e.Name(), err)
			os.Exit(1)
		}
		var findings []finding
		if err := json.Unmarshal(data, &findings); err != nil {
			fmt.Fprintf(os.Stderr, "aggregate: JSON invalide dans %s : %v\n", e.Name(), err)
			os.Exit(1)
		}
		all = append(all, findings...)
		parsedFiles++
	}

	sort.SliceStable(all, func(i, j int) bool {
		return rank(all[i].Severity) < rank(all[j].Severity)
	})

	fmt.Println("# Rapport de sécurité — Phase 1")
	fmt.Println()
	fmt.Printf("%d finding(s) sur %d fichier(s) de rapport.\n\n", len(all), parsedFiles)
	for _, f := range all {
		blocking := "bloquant"
		if !f.Blocking {
			blocking = "non bloquant (gap connu)"
		}
		fmt.Printf("## [%s] %s — %s (%s)\n\n", f.Severity, f.ID, f.Component, blocking)
		fmt.Printf("**Catégorie** : %s\n\n", f.Category)
		fmt.Printf("**Description** : %s\n\n", f.Description)
		if f.Payload != "" {
			fmt.Printf("**Payload** : `%s`\n\n", f.Payload)
		}
		fmt.Printf("**Attendu** : %s\n\n**Obtenu** : %s\n\n", f.Expected, f.Obtained)
		fmt.Printf("**Preuve** : %s\n\n", f.Evidence)
		fmt.Printf("**Remédiation** : %s\n\n", f.Remediation)
		if len(f.OWASP) > 0 {
			fmt.Printf("**OWASP** : %v", f.OWASP)
			if f.CWE != "" {
				fmt.Printf(" — **CWE** : %s", f.CWE)
			}
			fmt.Println()
			fmt.Println()
		}
	}

	blocking := 0
	for _, f := range all {
		if f.Blocking {
			blocking++
		}
	}
	if blocking > 0 {
		fmt.Printf("\n---\n\n**%d finding(s) bloquant(s)** — refus.\n", blocking)
		return 1
	}
	return 0
}
