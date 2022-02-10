package main

import (
	"fmt"

	"github.com/jedipunkz/ecrscan/pkg/myecr"
)

func main() {
	findings := myecr.ListFindings()
	fmt.Println(findings)
}
