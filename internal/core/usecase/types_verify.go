package usecase

// --- Verify ---

type Request struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	NowTime           string `json:"now_time,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

type VerifyResponse struct {
	VerificationData any  `json:"verification_data"`
	HasRemaining     bool `json:"has_remaining"`
	HasIntroduced    bool `json:"has_introduced"`
}
