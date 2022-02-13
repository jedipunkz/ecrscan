package main

import (
	"fmt"

	"github.com/jedipunkz/ecrscan/pkg/myecr"
	log "github.com/sirupsen/logrus"
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
		log.WithFields(log.Fields{
			"Name": f.Name,
		}).Info("")
		log.WithFields(log.Fields{
			"Severity": f.Severity,
		}).Info("")
		log.WithFields(log.Fields{
			"URI": f.URI,
		}).Info("")
		log.WithFields(log.Fields{
			"Description": f.Description,
		}).Info("")
	}

	// "INFORMATIONAL", "LOW", "MEDIUM", "HIGH",
	// "CRITICAL", "UNDEFINED" will be entered in k
	// ref: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageScanFindings.html#ECR-Type-ImageScanFindings-findingSeverityCounts
	for k, v := range finding.FindingSeverityCounts {
		fmt.Printf("Severity:%s Counts:%d\n", k, *v)
	}

	fmt.Printf("Vulunerability Source Updated At: %s\n", *finding.VulnerabilitySourceUpdatedAt)
	fmt.Printf("Image Scan Complated At: %s\n", *finding.ImageScanCompletedAt)
}
