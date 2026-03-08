package bugreport

import "regexp"

var (
	sensitiveKVRe = regexp.MustCompile(`(?im)^(\s*[^:=\n]*(?:secret|token|password|api[_-]?key|private[_-]?key|credential|auth[_-]?key|auth[_-]?token|access[_-]?key)[^:=\n]*\s*[:=]\s*)(.+)$`)
	akiaRe        = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	urlCredRe     = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@/\s]+@`)
)

func redactSensitiveBlob(data []byte) []byte {
	data = sensitiveKVRe.ReplaceAll(data, []byte("${1}[SANITIZED]"))
	data = akiaRe.ReplaceAll(data, []byte("[SANITIZED]"))
	data = urlCredRe.ReplaceAll(data, []byte("${1}[SANITIZED]@"))
	return data
}
