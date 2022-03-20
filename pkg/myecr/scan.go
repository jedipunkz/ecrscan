package myecr

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	log "github.com/sirupsen/logrus"
)

//Ecr is struct for communicating to aws ecr api
type Ecr struct {
	client             *ecr.ECR
	listFindings       *ecr.DescribeImageScanFindingsOutput
	input              *ecr.DescribeImageScanFindingsInput
	Repositories       [][]string
	Resion             string
	OutputScanFinding  ScanFinding
	OutputScanFindings ScanFindings
	OutputFinding      Finding
}

// Finding is struct for Output of DescribeImageScanFinding
type Finding struct {
	FindingSeverityCounts        map[string]*int64
	ImageScanCompletedAt         *time.Time
	VulnerabilitySourceUpdatedAt *time.Time
}

// ScanFinding is struct for Vulunerabilities of DescribeImageScanFinding
type ScanFinding struct {
	Name        string
	Severity    string
	Description string
	URI         string
}

// ScanFindings is struct for Vulunerability Findings
type ScanFindings []ScanFinding

// ListFindings is func
func (e *Ecr) ListFindings() (Finding, ScanFindings, error) {
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
		if err := e.getScanFindings(); err != nil {
			return e.OutputFinding, e.OutputScanFindings, err
		}
		if err := e.getFindings(); err != nil {
			return e.OutputFinding, e.OutputScanFindings, err
		}
	}
	return e.OutputFinding, e.OutputScanFindings, nil
}

func (e *Ecr) getScanFindings() error {
	var findings ScanFindings
	var finding ScanFinding

	resp, err := e.client.DescribeImageScanFindings(e.input)
	if err != nil {
		log.WithFields(log.Fields{
			"responce": resp,
		}).Fatal("DescribeImageScanFinding was failed.")
		return err
	}
	e.listFindings = resp

	for _, v := range e.listFindings.ImageScanFindings.Findings {
		if v.Description != nil {
			finding = ScanFinding{
				Name:        *v.Name,
				Description: *v.Description,
				URI:         *v.Uri,
				Severity:    *v.Severity,
			}
		} else {
			finding = ScanFinding{
				Name:        *v.Name,
				Description: "",
				URI:         *v.Uri,
				Severity:    *v.Severity,
			}
		}

		findings = append(findings, finding)
	}

	e.OutputScanFindings = findings
	return nil
}

func (e *Ecr) getFindings() error {
	resp, err := e.client.DescribeImageScanFindings(e.input)
	if err != nil {
		log.WithFields(log.Fields{
			"responce": resp,
		}).Fatal("DescribeImageScanFinding was failed.")
		return err
	}
	e.listFindings = resp

	e.OutputFinding = Finding{
		e.listFindings.ImageScanFindings.FindingSeverityCounts,
		e.listFindings.ImageScanFindings.ImageScanCompletedAt,
		e.listFindings.ImageScanFindings.VulnerabilitySourceUpdatedAt,
	}
	return nil
}
