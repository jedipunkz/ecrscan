package main

import (
	"fmt"

	"github.com/jedipunkz/ecrscan/pkg/myecr"
)

func main() {
	e := myecr.Ecr{}
	etcFinding, findings, _ := e.ListFindings()

	for _, f := range findings {
		fmt.Println(f.Name)
		fmt.Println(f.Severity)
		fmt.Println(f.URI)
		fmt.Println(f.Description)
	}

	for k, v := range etcFinding.FindingSeverityCounts {
		fmt.Println(k, *v)
	}

	fmt.Println(*etcFinding.VulnerabilitySourceUpdatedAt)
	fmt.Println(*etcFinding.ImageScanCompletedAt)
}
