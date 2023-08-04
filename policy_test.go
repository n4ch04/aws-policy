package awspolicy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var validatePolicies = []struct {
	inputPolicy  []byte
	outputPolicy Policy
	parsed       error
}{
	{
		inputPolicy: []byte(`
	{
		"Version": "2012-10-17",
		"ID": "1234",
		"Statement": [
			{
				"Principal": {"AWS":"*"},
				"Effect": "Allow",
				"Action": [
				  "sts:AssumeRole"
				],
				"Resource": [
				  "arn:aws:iam::99999999999:role/admin"
				]
			}
		]
	}		
	`), outputPolicy: Policy{
			Version: "2012-10-17",
			ID:      "1234",
			Statements: []Statement{
				{
					StatementID: "",
					Effect:      "Allow",
					Principal: map[string][]string{
						"AWS": {"*"},
					},
					Action: []string{
						"sts:AssumeRole",
					},
					Resource: []string{"arn:aws:iam::99999999999:role/admin"},
				}}}, parsed: nil,
	},
	{
		inputPolicy: []byte(`
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": [
							"athena:*"
						],
						"Resource": [
							"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"glue:GetDatabase",
							"glue:GetDatabases",
							"glue:CreateTable",
							"glue:UpdateTable",
							"glue:GetTable",
							"glue:GetTables",
							"glue:GetPartition",
							"glue:GetPartitions",
							"glue:BatchGetPartition",
							"glue:GetCatalogImportStatus"
						],
						"Resource": [
							"*"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"s3:GetObject",
							"s3:ListBucket",
							"s3:ListBucketMultipartUploads",
							"s3:ListMultipartUploadParts",
							"s3:AbortMultipartUpload",
							"s3:CreateBucket",
							"s3:ListAllMyBuckets",
							"s3:GetBucketLocation"
						],
						"Resource": [
							"arn:aws:s3:::bucket1",
							"arn:aws:s3:::bucket1/*"
						]
					}
				]
			}		
			`),
		outputPolicy: Policy{
			Version: "2012-10-17",
			ID:      "",
			Statements: []Statement{
				{
					Effect:    "Allow",
					Principal: map[string][]string{"*": {"*"}},
					Action:    []string{"athena:*"},
					Resource: []string{
						"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup",
					},
				}, {
					Effect: "Allow",
					Action: []string{
						"glue:GetDatabase",
						"glue:GetDatabases",
						"glue:CreateTable",
						"glue:UpdateTable",
						"glue:GetTable",
						"glue:GetTables",
						"glue:GetPartition",
						"glue:GetPartitions",
						"glue:BatchGetPartition",
						"glue:GetCatalogImportStatus"},
					Resource: []string{"*"},
				}, {
					Effect: "Allow",
					Action: []string{
						"s3:GetObject",
						"s3:ListBucket",
						"s3:ListBucketMultipartUploads",
						"s3:ListMultipartUploadParts",
						"s3:AbortMultipartUpload",
						"s3:CreateBucket",
						"s3:ListAllMyBuckets",
						"s3:GetBucketLocation"},
					Resource: []string{
						"arn:aws:s3:::bucket1",
						"arn:aws:s3:::bucket1/*",
					},
				}}}, parsed: nil,
	},
	{
		inputPolicy: []byte(`
	{
		"Version": "2012-10-17",
		"Id": "1234",
		"Statement": [
			{
				"StatementID": "1234",
				"Effect": "Allow",
				"Action": [
				  "sts:AssumeRole"
				],
				"Resource": [
				  "arn:aws:iam::99999999999:role/admin"
				]
			},
			{
				"Sid": "5678",
				"Effect": "Allow",
				"Action": [
				  "sts:AssumeRole"
				],
				"Resource": [
				  "arn:aws:iam::99999999999:role/admin"
				]
			}
		]
	}		
	`), outputPolicy: Policy{
			Version: "2012-10-17",
			ID:      "1234",
			Statements: []Statement{
				{
					StatementID: "1234",
					Effect:      "Allow",
					Action: []string{
						"sts:AssumeRole",
					},
					Resource: []string{"arn:aws:iam::99999999999:role/admin"},
				},
				{
					StatementID: "5678",
					Effect:      "Allow",
					Action: []string{
						"sts:AssumeRole",
					},
					Resource: []string{"arn:aws:iam::99999999999:role/admin"},
				}}}, parsed: nil,
	},
}

func TestParsePolicies(t *testing.T) {
	for _, test := range validatePolicies {
		var policy Policy
		t.Run(string(test.inputPolicy), func(t *testing.T) {
			got := policy.UnmarshalJSON(test.inputPolicy)
			if got != test.parsed {
				t.Errorf("Expected: %v, got: %v", test.parsed, got)
			}
			assert.Equal(t, test.outputPolicy.ID, policy.ID)
			assert.Equal(t, test.outputPolicy.Version, policy.Version)
			assert.Equal(t, test.outputPolicy.Statements, policy.Statements)
		})
	}
}
