// Command z3-validation drives the per-service Z3 validation
// experiment from the command line. The Makefile invokes it via
// `--service <name>` per service; the CLI looks up the service,
// discovers the relevant fixtures, and writes the per-service
// report under --output.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/experiments/z3-validation/crossservice"
	"github.com/sufield/stave/experiments/z3-validation/harness"
	"github.com/sufield/stave/experiments/z3-validation/services/cognito"
	"github.com/sufield/stave/experiments/z3-validation/services/iam"
	"github.com/sufield/stave/experiments/z3-validation/services/kms"
	"github.com/sufield/stave/experiments/z3-validation/services/network"
	"github.com/sufield/stave/experiments/z3-validation/services/s3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "z3-validation: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		serviceName  = flag.String("service", "", "service to run (s3|iam|kms|network|cognito|crossservice)")
		fixtureRoot  = flag.String("fixture-root", "../../testdata", "directory tree to scan for observation fixtures")
		fixtureGlob  = flag.String("fixture-filter", "", "substring filter on fixture path (empty = all)")
		staveBinary  = flag.String("stave-binary", "stave", "path to the stave CLI binary")
		controlsDir  = flag.String("controls", "", "absolute path to the stave controls directory (passed to stave apply --controls)")
		outputDir    = flag.String("output", "", "directory to write summary.json into (default: results/<service>/)")
		printSummary = flag.Bool("print", true, "print one-line summary to stderr after the run")
	)
	flag.Parse()

	svc, err := pickService(*serviceName)
	if err != nil {
		return err
	}

	out := *outputDir
	if out == "" {
		out = "results/" + svc.Name()
	}

	fixtures, err := harness.DiscoverFixtures(*fixtureRoot, func(path string) bool {
		if *fixtureGlob == "" {
			return true
		}
		return strings.Contains(path, *fixtureGlob)
	})
	if err != nil {
		return fmt.Errorf("discover fixtures under %s: %w", *fixtureRoot, err)
	}
	if len(fixtures) == 0 {
		fmt.Fprintf(os.Stderr, "no fixtures found under %s; report will be empty\n", *fixtureRoot)
	}

	report, err := harness.Run(context.Background(), harness.RunConfig{
		Service:     svc,
		StaveBinary: *staveBinary,
		ControlsDir: *controlsDir,
		FixtureDirs: fixtures,
		OutputDir:   out,
	})
	if err != nil {
		return err
	}

	if *printSummary {
		harness.PrintSummary(os.Stderr, report)
	}
	return nil
}

func pickService(name string) (harness.ServiceExperiment, error) {
	switch name {
	case "s3":
		return s3.New(), nil
	case "iam":
		return iam.New(), nil
	case "kms":
		return kms.New(), nil
	case "network":
		return network.New(), nil
	case "cognito":
		return cognito.New(), nil
	case "crossservice":
		return crossservice.New(), nil
	}
	return nil, fmt.Errorf("unknown --service %q (expected s3|iam|kms|network|cognito|crossservice)", name)
}
