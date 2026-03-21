package securityaudit

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func (r *SecurityAuditRunner) buildArtifactManifest(req SecurityAuditRequest, ev evidence.Bundle) securityaudit.ArtifactManifest {
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

	appendArtifact(securityaudit.ArtifactBuildInfo, ev.BuildInfo.RawJSON)
	appendArtifact(ev.SBOM.FileName, ev.SBOM.RawJSON)
	appendArtifact(securityaudit.ArtifactVulnReport, ev.Vuln.RawJSON)
	appendArtifact(securityaudit.ArtifactBinaryChecksums, ev.Binary.ChecksumJSON)
	if ev.Binary.SignatureJSON != nil {
		appendArtifact(securityaudit.ArtifactSignatureVerify, ev.Binary.SignatureJSON)
	}
	appendArtifact(securityaudit.ArtifactNetworkEgress, ev.Policy.Network.NetworkDeclJSON)
	appendArtifact(securityaudit.ArtifactFilesystemAccess, ev.Policy.Filesystem.FilesystemDeclJSON)
	appendArtifact(securityaudit.ArtifactControlCrosswalk, ev.Crosswalk.ResolutionJSON)

	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return manifest
}
