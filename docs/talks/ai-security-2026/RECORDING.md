# Recording Runbook — AI Security Demo

The repo ships everything that's deterministic about the recording.
The microphone-and-screen-capture pieces require a human. This
runbook is the human-driven checklist.

## What's in the repo

| Artifact | What it is | Buildable from repo? |
|---|---|---|
| `examples/demo-ai-security/run.sh` | The demo itself — one command, runs in 10s | ✅ shipped |
| `demo.tape` | VHS script for a deterministic GIF/MP4 (no voiceover) | ✅ shipped — run `vhs demo.tape` |
| `voiceover-script.md` | Narration lines + timing cues per act | ✅ shipped |
| `screenshots/act{1..5}-output.txt` | Per-act terminal output captures | ✅ shipped |
| `screenshots/full-output.txt` | End-to-end terminal capture | ✅ shipped |
| `demo-script.md` | Live-demo runbook (speaker cue sheet) | ✅ shipped |
| **MP4 with voiceover** | The actual recording | ❌ requires microphone + screen capture |
| **asciinema cast** | Real-time terminal recording for embed | ❌ requires interactive `asciinema rec` |
| **GIF** | README hero image | ❌ produced by `vhs demo.tape` — run when ready |

## Path 1 — Quick GIF for README (no voiceover)

The fastest path. Deterministic, scriptable, no microphone.

```bash
# Install VHS if not already
go install github.com/charmbracelet/vhs@latest

# Run the tape from repo root
vhs docs/talks/ai-security-2026/demo.tape
```

Output: `docs/talks/ai-security-2026/demo-ai-security.gif`
(~1.1 MB at the shipped settings — well under GitHub's 10 MB
hero-image cap). Drop this into the README as the hero image.
Tunables (font size, theme, dimensions) are at the top of
`demo.tape`.

**Sandbox hiccup, common in containers / CI:** if headless
Chrome's Zygote can't initialise (you'll see a
`ZygoteHostImpl::Init` crash and `recording failed`), prepend
`VHS_NO_SANDBOX=1`:

```bash
VHS_NO_SANDBOX=1 vhs docs/talks/ai-security-2026/demo.tape
```

This is the standard workaround when Chrome's setuid sandbox
binary isn't available — affects most rootless containers and
Codespaces variants. The flag disables the sandbox for the
single short-lived Chrome instance VHS spawns; it's
appropriate for a build-time rendering task running over
trusted local input.

## Path 2 — asciinema for embeddable terminal recording

```bash
# Install asciinema if not already
pip install --user asciinema

# Set up minimal prompt before recording
export PS1='$ '
clear

# Record
asciinema rec docs/talks/ai-security-2026/demo-ai-security.cast \
    --title "AI Security Demo — Stave" \
    --cols 100 --rows 35

# Inside the recording:
bash examples/demo-ai-security/run.sh

# Stop with Ctrl-D after the demo finishes

# Verify locally
asciinema play docs/talks/ai-security-2026/demo-ai-security.cast

# Upload to asciinema.org (returns a URL)
asciinema upload docs/talks/ai-security-2026/demo-ai-security.cast
```

The upload returns a URL like `https://asciinema.org/a/XXXXX`. Embed
in dev.to with `{% asciinema XXXXX %}` and in the GitHub README
with the asciinema.svg badge linking to that URL.

## Path 3 — Full MP4 with voiceover (conference backup)

Requires: screen recorder (OBS, QuickTime, Loom) + microphone +
quiet room + post-production tool.

### Capture session checklist

- [ ] Terminal at full-screen, font 18–20pt, dark background
- [ ] Prompt stripped: `export PS1='$ '` then `clear`
- [ ] No tabs, no split panes, no IDE chrome
- [ ] Microphone test recording (10s, played back to check levels)
- [ ] Browser tabs closed, notifications muted, phone silenced
- [ ] OBS / QuickTime configured for 1080p, 30fps, H.264

### Recording flow

1. Start screen recorder + microphone capture (single recording)
2. Hold for 2 seconds of dead air (trim in post)
3. Read the pre-roll line from `voiceover-script.md`
4. Type and run `bash examples/demo-ai-security/run.sh`
5. For each of the 5 acts, wait for the divider to print, then
   read the act's voiceover from `voiceover-script.md`. The
   terminal scrolls fast; the audience is reading and listening
   in parallel.
6. After Act 5's closing line ("That's the gap."), pause 5 seconds
7. Read the outro line
8. Hold 3 seconds of post-roll
9. Stop recording

Total: 6:15–6:30. Trim head and tail dead air in post.

### Post-production

- Cut the head/tail dead air
- Normalize audio so voiceover sits clearly over silence (no
  background music — this is technical content, not a launch
  video)
- Add a text overlay at 0:00: `AI Security Demo — github.com/sufield/stave`
- Add a text overlay at the close: same URL + `Open source. Air-gapped. 9 reasoning engines.`
- Export at 1080p, H.264, ~8 Mbps. Final file size ~50–80 MB for
  YouTube upload; smaller (10–20 MB) if compressed for dev.to.

### Upload destinations

| Destination | Format | Visibility |
|---|---|---|
| YouTube (Stave channel) | MP4 1080p | Unlisted, link from README |
| dev.to article | embedded YouTube or `{% asciinema %}` | Public when article goes live |
| GitHub README | GIF (Path 1) | Always-on hero |
| LinkedIn / Bluesky | MP4 trimmed to ≤2 min | Time-bounded promo |

## Fallback for conference talk

If the live demo fails on stage (Codespace times out, network
drops, devcontainer hasn't finished building), the speaker pulls
up the static text screenshots:

```
docs/talks/ai-security-2026/screenshots/
├── act1-output.txt   — 5 findings list
├── act2-output.txt   — 3 CRITICAL compound chains
├── act3-output.txt   — 5,300 facts + encoding 9/9
├── act4-output.txt   — remediation + "All AI controls pass"
├── act5-output.txt   — illustrative scanner output + closing line
├── outro.txt         — summary table
└── full-output.txt   — full end-to-end capture
```

These are plain UTF-8 text. Open in a full-screen text editor
on stage if the live demo fails; the audience sees real captured
output (label it "captured run output" in the slide deck so
they know it's not a screenshot of a screenshot).

If the MP4 / GIF artifact also exists, that's the second fallback.
Have it queued in a browser tab on a second monitor before going
on stage.

## What NOT to do

1. **Don't record without the prompt stripped.** A `user@hostname:~/work/bizacademy/stave$` prompt is 30 columns of noise. Strip it with `PS1='$ '`.
2. **Don't speed up the recording.** Real-time or slightly slower. The audience reads at the runner's natural cadence.
3. **Don't add background music.** Technical demo, not a product launch.
4. **Don't narrate the code.** Narrate the security story.
5. **Don't record longer than 8 minutes.** If you can't fit it with narration, cut the architecture context and link to the dev.to article instead.

## Quality gate before publishing

Before pushing the MP4 or asciinema cast public, verify:

- [ ] Audio levels uniform from start to finish (no spikes)
- [ ] No personal identifiers in the terminal (`~/work/bizacademy/...` is fine, AWS account IDs in the fixtures are obviously fake `111122223333`)
- [ ] Final frame holds the GitHub URL long enough to read
- [ ] Closed captions / transcript prepared from `voiceover-script.md`
  (paste into YouTube's caption editor; YouTube auto-transcribes
  but the manual edit ensures the chain names are spelled right)
- [ ] Title and description include the key phrase "compound risk
  detection" — that's the SEO term operators search for

The repo already carries everything except the audio + the GIF.
Path 1 (VHS GIF) takes 30 seconds once you have `vhs` installed;
Path 2 (asciinema cast) takes the demo's runtime; Path 3 (MP4 +
voiceover) is a half-day human task with quality gates.
