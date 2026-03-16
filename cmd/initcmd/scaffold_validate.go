package initcmd

import (
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func validateScaffoldInputs(rawDir, profile, cadence string) (string, error) {
	dir := fsutil.CleanUserPath(rawDir)
	if dir == "" {
		return "", &ui.UserError{Err: fmt.Errorf("--dir cannot be empty")}
	}
	if profile != "" && profile != profileAWSS3 {
		return "", &ui.UserError{Err: fmt.Errorf("unsupported --profile %q (supported: aws-s3)", profile)}
	}
	if cadence != cadenceDaily && cadence != cadenceHourly {
		return "", &ui.UserError{Err: fmt.Errorf("unsupported --capture-cadence %q (supported: daily, hourly)", cadence)}
	}
	return dir, nil
}
