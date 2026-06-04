//go:build windows

package fsutil

// openNoFollow has no effect on Windows (no O_NOFOLLOW). On this platform the
// post-open verifyHandle check plus truncate-after-verify in SafeCreateFile are
// the symlink-swap backstop.
const openNoFollow = 0
