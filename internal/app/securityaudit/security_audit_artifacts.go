package securityaudit

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

func (r *SecurityAuditRunner) buildArtifactManifest(req SecurityAuditRequest, ev evidenceBundle) securityaudit.ArtifactManifest {
	manifest := securityaudit.ArtifactManifest{
		SchemaVersion: kernel.SchemaSecurityAuditArtifacts,
		GeneratedAt:   req.Now.UTC().Format(time.RFC3339),
		BundleDir:     req.OutDir,
		Files:         make([]securityaudit.ArtifactEntry, 0, 10),
	}

	appendArtifact := func(path string, payload []byte) {
		if len(payload) == 0 || strings.TrimSpace(path) == "" {
			return
		}
		manifest.Files = append(manifest.Files, securityaudit.ArtifactEntry{
			Path:      filepath.Clean(path),
			SHA256:    string(r.hashBytes(payload)),
			SizeBytes: int64(len(payload)),
			Content:   payload,
		})
	}

	appendArtifact(securityaudit.ArtifactBuildInfo, ev.buildInfo.RawJSON)
	appendArtifact(ev.sbom.FileName, ev.sbom.RawJSON)
	appendArtifact(securityaudit.ArtifactVulnReport, ev.vuln.RawJSON)
	appendArtifact(securityaudit.ArtifactBinaryChecksums, ev.binary.ChecksumJSON)
	if ev.binary.SignatureJSON != nil {
		appendArtifact(securityaudit.ArtifactSignatureVerify, ev.binary.SignatureJSON)
	}
	appendArtifact(securityaudit.ArtifactNetworkEgress, ev.policy.Network.NetworkDeclJSON)
	appendArtifact(securityaudit.ArtifactFilesystemAccess, ev.policy.Filesystem.FilesystemDeclJSON)
	appendArtifact(securityaudit.ArtifactControlCrosswalk, ev.crosswalk.ResolutionJSON)

	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return manifest
}
