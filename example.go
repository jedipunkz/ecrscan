package main

import (
	"fmt"

	"github.com/jedipunkz/ecrscan/pkg/myecr"
)

func main() {
	e := myecr.Ecr{}
	findings, _ := e.ListFindings()
	// fmt.Println(findings)
	for _, f := range findings {
		fmt.Println(f.Name)
		fmt.Println(f.Severity)
		fmt.Println(f.URI)
		fmt.Println(f.Description)
	}
}
