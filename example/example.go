package main

import (
	"fmt"

	"github.com/jedipunkz/ecrscan/pkg/myecr"
)

func main() {
	e := myecr.Ecr{}
	// define ECR Repositories to scan
	e.Repositories = [][]string{
		{"scantest", "latest"},
	}
	e.Resion = "ap-northeast-1"
	// scan and get vulunerability findings
	finding, vulFindings, _ := e.ListFindings()

	for _, f := range vulFindings {
		fmt.Println(f.Name)
		fmt.Println(f.Severity)
		fmt.Println(f.URI)
		fmt.Println(f.Description)
	}

	// "INFORMATIONAL", "LOW", "MEDIUM", "HIGH",
	// "CRITICAL", "UNDEFINED" will be entered in k
	// ref: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageScanFindings.html#ECR-Type-ImageScanFindings-findingSeverityCounts
	for k, v := range finding.FindingSeverityCounts {
		fmt.Println(k, *v)
	}

	fmt.Println(*finding.VulnerabilitySourceUpdatedAt)
	fmt.Println(*finding.ImageScanCompletedAt)
}
