package policy

import (
	"testing"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
)

func FuzzEvaluate(f *testing.F) {
	seeds := []string{
		``,
		`{`,
		`{}`,
		`{"Version":"2012-10-17","Statement":[]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:PutObject","s3:PutObjectAcl"],"Resource":"arn:aws:s3:::example/*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::*:root"},"Action":"s3:*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	eval := NewEvaluator(nil, s3resolver.NewResolver())

	f.Fuzz(func(t *testing.T, input string) {
		doc, _ := Parse(input)
		eval.Evaluate(doc)
	})
}
