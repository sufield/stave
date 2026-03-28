package kernel

// ObservationSourceType identifies the extraction method that produced an observation.
type ObservationSourceType string

func (t ObservationSourceType) String() string { return string(t) }

// IsEmpty reports whether the source type is unset.
func (t ObservationSourceType) IsEmpty() bool { return t == "" }
