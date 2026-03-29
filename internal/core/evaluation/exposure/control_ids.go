package exposure

import "github.com/sufield/stave/internal/core/kernel"

// exposureControlSet is the single source of truth for all exposure
// classification control IDs. Every ID used in this package MUST be
// defined here. ValidateControlIDs iterates all() to validate format.
type exposureControlSet struct {
	resourceTakeover    kernel.ControlID
	webPublic           kernel.ControlID
	authenticatedRead   kernel.ControlID
	publicRead          kernel.ControlID
	resourcePublicRead  kernel.ControlID
	publicList          kernel.ControlID
	publicWrite         kernel.ControlID
	resourcePublicWrite kernel.ControlID
	publicAdminRead     kernel.ControlID
	publicAdminWrite    kernel.ControlID
	publicDelete        kernel.ControlID
}

// all returns every registered exposure control ID. This is the ONLY
// enumeration point — ValidateControlIDs and tests derive from it.
func (s *exposureControlSet) all() []kernel.ControlID {
	return []kernel.ControlID{
		s.resourceTakeover,
		s.webPublic,
		s.authenticatedRead,
		s.publicRead,
		s.resourcePublicRead,
		s.publicList,
		s.publicWrite,
		s.resourcePublicWrite,
		s.publicAdminRead,
		s.publicAdminWrite,
		s.publicDelete,
	}
}

// exposureIDs holds the canonical exposure classification IDs (cloud-neutral).
var exposureIDs = exposureControlSet{
	resourceTakeover:    "CTL.STORAGE.TAKEOVER.001",
	webPublic:           "CTL.STORAGE.WEBSITE.PUBLIC.001",
	authenticatedRead:   "CTL.STORAGE.GLOBAL.AUTHENTICATED.READ.001",
	publicRead:          "CTL.STORAGE.PUBLIC.READ.001",
	resourcePublicRead:  "CTL.STORAGE.RESOURCE.PUBLIC.READ.001",
	publicList:          "CTL.STORAGE.PUBLIC.LIST.001",
	publicWrite:         "CTL.STORAGE.PUBLIC.WRITE.001",
	resourcePublicWrite: "CTL.STORAGE.RESOURCE.PUBLIC.WRITE.001",
	publicAdminRead:     "CTL.STORAGE.PUBLIC.ADMIN.READ.001",
	publicAdminWrite:    "CTL.STORAGE.PUBLIC.ADMIN.WRITE.001",
	publicDelete:        "CTL.STORAGE.PUBLIC.DELETE.001",
}
