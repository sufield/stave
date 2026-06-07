package stave

import "github.com/sufield/stave/internal/core/kernel"

// ObservationSchemaVersion is the schema_version string that observation
// snapshot files carry (obs.v0.1). Re-exported from the kernel so command
// packages — e.g. the `stave generate observation` scaffolding — can
// reference the canonical value without importing internal/.
const ObservationSchemaVersion = string(kernel.SchemaObservation)
