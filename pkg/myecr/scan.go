package myecr

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

//Ecr is struct for communicating to aws ecr api
type Ecr struct {
	client           *ecr.ECR
	listFindings     *ecr.DescribeImageScanFindingsOutput
	input            *ecr.DescribeImageScanFindingsInput
	Repositories     [][]string
	Resion           string
	OutputFinding    Finding
	OutputFindings   Findings
	EtcOutputFinding EtcFinding
}

// EtcFinding is struct
type EtcFinding struct {
	FindingSeverityCounts        map[string]*int64
	ImageScanCompletedAt         *time.Time
	VulnerabilitySourceUpdatedAt *time.Time
}

// Finding is struct for Vulunerabilities
type Finding struct {
	Name        string
	Severity    string
	Description string
	URI         string
	// FindingSeverityCounts map[string]*int64
}

// Findings is struct for Vulunerability Findings
type Findings []Finding

// ListFindings is func
func (e *Ecr) ListFindings() (EtcFinding, Findings, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String(e.Resion),
		},
	}))
	e.client = ecr.New(sess)

	for _, r := range e.Repositories {
		e.input = &ecr.DescribeImageScanFindingsInput{
			ImageId: &ecr.ImageIdentifier{
				ImageTag: aws.String(r[1]),
			},
			RepositoryName: aws.String(r[0]),
		}
		if err := e.getOutputFindings(); err != nil {
			return e.EtcOutputFinding, e.OutputFindings, err
		}
	}
	return e.EtcOutputFinding, e.OutputFindings, nil
}

func (e *Ecr) getOutputFindings() error {
	var findings Findings
	var finding Finding
	// var etcFinding EtcFinding

	resp, err := e.client.DescribeImageScanFindings(e.input)
	if err != nil {
		log.Fatal(err)
		return err
	}
	e.listFindings = resp

	for _, v := range e.listFindings.ImageScanFindings.Findings {
		if v.Description != nil {
			finding = Finding{
				Name:        *v.Name,
				Description: *v.Description,
				URI:         *v.Uri,
				Severity:    *v.Severity,
				// FindingSeverityCounts: e.listFindings.ImageScanFindings.FindingSeverityCounts,
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

	e.EtcOutputFinding = EtcFinding{
		e.listFindings.ImageScanFindings.FindingSeverityCounts,
		e.listFindings.ImageScanFindings.ImageScanCompletedAt,
		e.listFindings.ImageScanFindings.VulnerabilitySourceUpdatedAt,
	}
	e.OutputFindings = findings
	return nil
}
