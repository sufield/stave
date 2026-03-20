package asset

// Tags returns normalized scope tags for asset filtering.
func (r Asset) Tags() TagSet {
	rawTags := r.Metadata().GetPath("storage.tags").StringMap()
	if len(rawTags) == 0 {
		return NewTagSet(nil)
	}

	return NewTagSet(rawTags)
}

// HasTagMatch reports whether the asset has a normalized tag key/value match.
// If allowedValues is empty, any non-empty value for key is considered a match.
func (r Asset) HasTagMatch(key string, allowedValues map[string]struct{}) bool {
	return r.Tags().Matches(key, allowedValues)
}
