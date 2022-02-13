# ecrscan

ecrscan is golang package to scan AWS ECR Repositories and get vulunerability information.

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/jedipunkz/ecrscan/Go-Lint?style=flat-square)](https://github.com/jedipunkz/ecrscan/actions?query=workflow%3AGo-Lint)

## Requirement

- install go 1.17.x or later

## Usage

Example is here:

```go
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
```

Output:

```
...
<snip>
INFO[0001]                                               Name=CVE-2017-11164
INFO[0001]                                               Severity=INFORMATIONAL
INFO[0001]                                               URI="http://people.ubuntu.com/~ubuntu-security/cve/CVE-2017-11164"
INFO[0001]                                               Description="In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression."
Severity:INFORMATIONAL Counts:4
Severity:MEDIUM Counts:2
Severity:LOW Counts:12
Vulunerability Source Updated At: 2021-04-20 23:07:00 +0000 UTC
Image Scan Complated At: 2021-04-23 08:07:05 +0000 UTC
```

## License

[Apache License 2.0](https://github.com/jedipunkz/awscreds/blob/main/LICENSE)

## Author

[jedipunkz 🚀](https://twitter.com/jedipunkz)
