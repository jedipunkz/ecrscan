package myecr

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

//Ecr is struct for communicating to ecr api
type Ecr struct {
	client         *ecr.ECR
	listFindings   *ecr.DescribeImageScanFindingsOutput
	input          *ecr.DescribeImageScanFindingsInput
	OutputFindings Findings
}

// Finding is struct for Vulunerabilities
type Finding struct {
	Name        string
	Severity    string
	Description string
	URI         string
}

// Findings is struct for Vulunerability Findings
type Findings []Finding

var (
	repositories = [][]string{
		{"scantest", "latest"},
	}
)

const (
	region = "ap-northeast-1"
)

// ListFindings is func
func (e *Ecr) ListFindings() (Findings, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String(region),
		},
	}))
	e.client = ecr.New(sess)

	for _, r := range repositories {
		e.input = &ecr.DescribeImageScanFindingsInput{
			ImageId: &ecr.ImageIdentifier{
				ImageTag: aws.String(r[1]),
			},
			RepositoryName: aws.String(r[0]),
		}
		if err := e.getOutputFindings(); err != nil {
			log.Fatal(err)
			return nil, err
		}
	}
	return e.OutputFindings, nil
}

func (e *Ecr) getOutputFindings() error {
	var findings Findings
	var finding Finding

	resp, err := e.client.DescribeImageScanFindings(e.input)
	e.listFindings = resp
	if err != nil {
		log.Fatal(err)
		return err
	}

	for _, v := range e.listFindings.ImageScanFindings.Findings {
		if v.Description != nil {
			finding = Finding{
				Name:        *v.Name,
				Description: *v.Description,
				URI:         *v.Uri,
				Severity:    *v.Severity,
			}
		} else {
			finding = Finding{
				Name:        *v.Name,
				Description: "",
				URI:         *v.Uri,
				Severity:    *v.Severity,
			}
		}

		findings = append(findings, finding)
	}
	e.OutputFindings = findings
	return nil
}
