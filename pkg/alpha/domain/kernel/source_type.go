package kernel

// ObservationSourceType identifies the extraction method that produced an observation.
type ObservationSourceType string

const (
	SourceTypeAWSS3Snapshot ObservationSourceType = "aws-s3-snapshot"
)

func (t ObservationSourceType) String() string { return string(t) }

// IsEmpty reports whether the source type is unset.
func (t ObservationSourceType) IsEmpty() bool { return t == "" }
