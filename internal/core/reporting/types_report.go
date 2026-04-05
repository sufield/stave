package reporting

import "github.com/sufield/stave/internal/safetyenvelope"

// --- Report ---

type ReportRequest struct {
	InputFile    string `json:"input_file"`
	TemplateFile string `json:"template_file,omitempty"`
	Format       string `json:"format,omitempty"`
	Quiet        bool   `json:"quiet,omitempty"`
}

type ReportResponse struct {
	EvaluationData *safetyenvelope.Evaluation `json:"evaluation_data"`
}
