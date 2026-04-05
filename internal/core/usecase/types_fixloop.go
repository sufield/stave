package usecase

// --- Fix Loop ---

type FixLoopRequest struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	OutDir            string `json:"out_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	NowTime           string `json:"now_time,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

type FixLoopResponse struct {
	ReportData    any  `json:"report_data"`
	HasViolations bool `json:"has_violations"`
}
