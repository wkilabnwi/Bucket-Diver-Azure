package models

import "time"

type Finding struct {
	Bucket    string    `json:"bucket"`
	File      string    `json:"file"`
	Line      int       `json:"line,omitempty"`
	Secret    string    `json:"secret"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

type ScanTask struct {
	Bucket string
	Key    string
}

var severityMap = map[string]string{
	"AWS_ACCESS_KEY":         "CRITICAL",
	"AWS_SECRET_KEY":         "CRITICAL",
	"AZURE_KEY":              "CRITICAL",
	"GCP_SERVICE_KEY":        "CRITICAL",
	"PRIVATE_KEY":            "CRITICAL",
	"DB_URL":                 "HIGH",
	"STRIPE_KEY":             "HIGH",
	"GITHUB_TOKEN":           "HIGH",
	"SLACK_WEBHOOK":          "MEDIUM",
	"SLACK_TOKEN":            "MEDIUM",
	"JWT_SECRET":             "MEDIUM",
	"GOOGLE_KEY":             "MEDIUM",
	"SENDGRID_KEY":           "MEDIUM",
	"TWILIO_KEY":             "MEDIUM",
	"NPM_TOKEN":              "MEDIUM",
	"PYPI_TOKEN":             "MEDIUM",
	"TERRAFORM_CLOUD_TOKEN":  "MEDIUM",
	"DATADOG_API_KEY":        "LOW",
	"HIGH_ENTROPY_CANDIDATE": "LOW",
	"HIGH_ENTROPY_METADATA":  "LOW",
}

func NewFinding(bucket, file string, line int, secret, category string) Finding {
	sev, ok := severityMap[category]
	if !ok {
		sev = "INFO"
	}
	return Finding{
		Bucket:    bucket,
		File:      file,
		Line:      line,
		Secret:    secret,
		Category:  category,
		Severity:  sev,
		Timestamp: time.Now().UTC(),
	}
}
