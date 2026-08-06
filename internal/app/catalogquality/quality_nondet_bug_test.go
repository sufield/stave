package catalogquality

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnalyze_BlindSpotsDeterministic(t *testing.T) {
	in := Input{
		AssetTypes: map[kernel.AssetType]int{
			"aws_lambda_function": 10,
			"aws_s3_bucket":       5,
			"aws_iam_role":        20,
			"aws_ec2_instance":    15,
		},
	}

	first := Analyze(in)
	wantBlindSpots := []BlindSpot{
		{AssetType: "aws_ec2_instance", AssetCount: 15},
		{AssetType: "aws_iam_role", AssetCount: 20},
		{AssetType: "aws_lambda_function", AssetCount: 10},
		{AssetType: "aws_s3_bucket", AssetCount: 5},
	}

	for range 100 {
		rep := Analyze(in)
		if !reflect.DeepEqual(rep.BlindSpots, wantBlindSpots) {
			t.Fatalf("non-deterministic BlindSpots ordering: got %v, want %v (first got %v)", rep.BlindSpots, wantBlindSpots, first.BlindSpots)
		}
	}
}
