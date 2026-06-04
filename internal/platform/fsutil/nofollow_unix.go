//go:build !windows

package fsutil

import "syscall"

// openNoFollow makes os.OpenFile fail (ELOOP) when the final path component is
// a symlink, instead of following it. Combined with truncate-after-verify in
// SafeCreateFile, this closes the TOCTOU window where a symlink swapped in
// between CheckSymlinkSafety and the open could redirect (and O_TRUNC could
// truncate) an attacker-chosen target.
const openNoFollow = syscall.O_NOFOLLOW
