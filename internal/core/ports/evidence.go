package ports

// EvidenceBundler packages assessment results into a portable,
// cryptographically sealed evidence archive for air-gap transfer.
// Input types are defined in the adapter layer to avoid import
// cycles with core packages.
type EvidenceBundler interface {
	Package(assessmentJSON, traceJSON, snapshotsJSON, privateKeyPEM []byte) ([]byte, error)
}
