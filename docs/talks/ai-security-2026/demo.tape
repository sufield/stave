# VHS tape for the AI security demo recording.
# Deterministic, scriptable, no microphone required. Produces an
# animated GIF/MP4 suitable for the GitHub README hero image and
# the dev.to article embed.
#
# Run from repo root (so `examples/demo-ai-security/run.sh` resolves):
#
#     vhs docs/talks/ai-security-2026/demo.tape
#
# Output: docs/talks/ai-security-2026/demo-ai-security.gif
#
# Tunables: bump FontSize to 24 for projector capture; drop to 14
# for a tight README hero; widen Width to 1400 for full-line
# rendering of the chain descriptions.

Output docs/talks/ai-security-2026/demo-ai-security.gif

Set Shell        "bash"
Set FontSize     16
Set Width        1280
Set Height       820
Set Theme        "Dracula"
Set TypingSpeed  50ms
Set PlaybackSpeed 1.0

# Minimal prompt — strip the bash clutter so the audience sees the
# demo, not the user@host:cwd noise.
Hide
Type "export PS1='$ ' && clear"
Enter
Show

# The one keystroke of the demo.
Type "bash examples/demo-ai-security/run.sh"
Sleep 1s
Enter

# The demo runs ~10s wall-clock in the devcontainer; sleep covers
# the longest plausible runtime plus a tail of dead air so the
# audience reads the final summary.
Sleep 25s
