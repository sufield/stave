#!/usr/bin/env bash
# Stave adopter bootstrap — one command on a fresh Ubuntu machine.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sufield/stave/main/scripts/bootstrap.sh | bash
#
# Or locally:
#   bash scripts/bootstrap.sh
#
# What it does:
#   0. Installs system packages if missing (git, curl, make, jq)
#   1. Installs mise (if not already installed)
#   2. Activates mise in the current shell
#   3. Clones Stave (mise.toml is in the repo)
#   4. Runs `mise install` to get Go 1.27.3 and golangci-lint 2.14.0
#   5. Runs `mise run build` to build the stave binary
#
# After it finishes:
#   stave apply --observations ./observations
#
set -euo pipefail

STAVE_DIR="${STAVE_DIR:-$HOME/stave}"

echo "╔══════════════════════════════════════════╗"
echo "║  Stave Bootstrap                         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 0. System packages ──────────────────────────────────────────────
echo "==> Checking system dependencies..."
MISSING=()
for cmd in git curl make jq; do
  command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "    Installing: ${MISSING[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y -qq "${MISSING[@]}"
fi

# ── 1. Install mise ──────────────────────────────────────────────────
if ! command -v mise &>/dev/null; then
  echo "==> Installing mise..."
  curl -fsSL https://mise.run | sh
  export PATH="$HOME/.local/bin:$PATH"
else
  echo "==> mise already installed: $(mise --version)"
fi

# ── 2. Activate mise ─────────────────────────────────────────────────
eval "$(mise activate bash)"

# ── 3. Clone Stave ───────────────────────────────────────────────────
if [ ! -d "$STAVE_DIR/.git" ]; then
  echo "==> Cloning Stave..."
  git clone https://github.com/sufield/stave.git "$STAVE_DIR"
else
  echo "==> Stave already cloned at $STAVE_DIR"
fi

cd "$STAVE_DIR"

# ── 4. Install tools ─────────────────────────────────────────────────
echo "==> Installing Go 1.27.3 and golangci-lint 2.14.0 via mise..."
mise install

# ── 5. Build stave ───────────────────────────────────────────────────
echo "==> Building stave..."
mise run build

echo ""
echo "==> Done. stave is at: $(command -v stave 2>/dev/null || echo "$STAVE_DIR/stave")"
echo ""
echo "  Next: capture observations and evaluate:"
echo "    stave apply --observations ./observations"
echo ""

# ── 6. Shell integration (idempotent) ────────────────────────────────
SHELL_RC="$HOME/.bashrc"
if [ -f "$HOME/.zshrc" ] && [[ "${SHELL:-}" == *zsh* ]]; then
  SHELL_RC="$HOME/.zshrc"
fi

ACTIVATE_CMD='eval "$(~/.local/bin/mise activate bash)"'
if [[ "${SHELL:-}" == *zsh* ]]; then
  ACTIVATE_CMD='eval "$(~/.local/bin/mise activate zsh)"'
fi

if ! grep -q 'mise activate' "$SHELL_RC" 2>/dev/null; then
  echo '' >> "$SHELL_RC"
  echo '# mise — dev tool manager' >> "$SHELL_RC"
  echo "$ACTIVATE_CMD" >> "$SHELL_RC"
  echo "==> Added mise activation to $SHELL_RC"
fi
