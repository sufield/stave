package securityaudit

import "github.com/sufield/stave/internal/doctor"

type defaultDiagnosticsService struct{}

func (defaultDiagnosticsService) Run(ctx doctor.Context) ([]doctor.Check, bool) {
	return doctor.Run(ctx)
}
