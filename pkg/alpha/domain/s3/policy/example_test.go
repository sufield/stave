package policy_test

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/pkg/alpha/domain/s3/policy"
)

func ExampleParse() {
	doc, err := policy.Parse(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	assessment := doc.Assess()
	fmt.Println("allows_public_read:", assessment.AllowsPublicRead)
	// Output: allows_public_read: true
}

func ExampleNewEvaluator() {
	doc, _ := policy.Parse(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`)

	report := policy.NewEvaluator(nil).Evaluate(doc)
	out, _ := json.Marshal(report.Score)
	fmt.Println("risk_score:", string(out))
	// Output: risk_score: 90
}
