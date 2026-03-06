package bugreport

import "regexp"

var (
	sensitiveKVRe = regexp.MustCompile(`(?im)^(\s*[^:=\n]*(?:secret|token|password|api[_-]?key|private[_-]?key|credential|auth|access[_-]?key)[^:=\n]*\s*[:=]\s*)(.+)$`)
	akiaRe        = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	urlCredRe     = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@/\s]+@`)
)

func redactSensitiveBlob(data []byte) []byte {
	s := string(data)
	s = sensitiveKVRe.ReplaceAllString(s, "${1}[SANITIZED]")
	s = akiaRe.ReplaceAllString(s, "[SANITIZED]")
	s = urlCredRe.ReplaceAllString(s, "${1}[SANITIZED]@")
	return []byte(s)
}
