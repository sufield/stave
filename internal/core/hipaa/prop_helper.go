package hipaa

import "github.com/sufield/stave/internal/core/asset"

// storageMap extracts the storage sub-map from an asset's properties.
func storageMap(a asset.Asset) map[string]any {
	s, _ := a.Properties["storage"].(map[string]any)
	return s
}

// encryptionMap extracts storage.encryption from an asset.
func encryptionMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	e, _ := s["encryption"].(map[string]any)
	return e
}

// versioningMap extracts storage.versioning from an asset.
func versioningMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	v, _ := s["versioning"].(map[string]any)
	return v
}

// accessMap extracts storage.access from an asset.
func accessMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	m, _ := s["access"].(map[string]any)
	return m
}

// networkMap extracts storage.network from an asset.
func networkMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	m, _ := s["network"].(map[string]any)
	return m
}

// loggingMap extracts storage.logging from an asset.
func loggingMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	m, _ := s["logging"].(map[string]any)
	return m
}

// toString extracts a string from an interface value.
func toString(v any) string {
	s, _ := v.(string)
	return s
}
