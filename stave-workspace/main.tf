# Coder workspace template for Stave.
#
# Pairs with stave-workspace/Dockerfile (iter 1) — that image is what
# the workspace runs in. The template uses Coder's Docker provider so
# it works with Coder OSS (no Premium-only resources).
#
# Import:
#   coder templates push stave --directory stave-workspace
#
# Provision:
#   coder create my-stave --template stave
#
# The build context for the docker image is the stave module root,
# one level up from this file (so the Dockerfile's COPY directives
# reach controls/, chains/, examples/, etc.). `context = "../"`
# wires that up.

terraform {
  required_providers {
    coder = {
      source  = "coder/coder"
      version = "~> 1.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

# ─── Inputs ──────────────────────────────────────────────────────────

data "coder_workspace" "me" {}
data "coder_workspace_owner" "me" {}

# Adopters can point at their own fork at create time. Default is
# the canonical repo; the workspace's startup script clones it into
# ~/stave for in-place editing alongside the read-only /opt/stave/
# tree the image ships.
data "coder_parameter" "git_repo" {
  name         = "git_repo"
  display_name = "Git repository"
  description  = "Stave repo to clone into ~/stave (your fork, or the canonical repo)."
  default      = "https://github.com/sufield/stave.git"
  type         = "string"
  mutable      = true
}

# ─── Agent ───────────────────────────────────────────────────────────

resource "coder_agent" "main" {
  os             = "linux"
  arch           = "amd64"
  startup_script = <<-EOT
    set -e

    # Clone the repo into ~/stave for editing. The image already
    # ships a read-only copy at /opt/stave/ for runtime use; this
    # clone is for adopters who want to modify controls / extend
    # the catalog / contribute back.
    if [ ! -d "$HOME/stave/.git" ]; then
      git clone "${data.coder_parameter.git_repo.value}" "$HOME/stave" || true
    fi

    # Background stave-mcp for MCP clients (VS Code MCP extension,
    # Claude Desktop) to connect to. Stdio-only; the log captures
    # any startup error a curious adopter wants to inspect.
    if ! pgrep -x stave-mcp > /dev/null; then
      stave-mcp > /tmp/stave-mcp.log 2>&1 &
    fi

    # Print the START-HERE banner once. Shells inherit the MOTD
    # from /etc/profile.d/stave-motd.sh on every login.
    cat /opt/stave/guides/START-HERE.md
  EOT

  # Sidebar metadata. Each script runs inside the workspace and
  # caches its output for the interval shown.
  metadata {
    display_name = "Stave version"
    key          = "stave_version"
    script       = "stave version 2>/dev/null | head -1"
    interval     = 86400
    timeout      = 5
  }

  metadata {
    display_name = "Controls"
    key          = "control_count"
    # `stave features` prints "2658 controls across 53 packs" —
    # extract just the number for the sidebar tile.
    script       = "stave features 2>/dev/null | grep -oE '[0-9]+ controls' | head -1"
    interval     = 86400
    timeout      = 5
  }

  metadata {
    display_name = "MCP server"
    key          = "mcp_status"
    script       = "pgrep -x stave-mcp >/dev/null && echo running || echo stopped"
    interval     = 60
    timeout      = 5
  }
}

# ─── Apps surfaced in the Coder dashboard ────────────────────────────

resource "coder_app" "code-server" {
  agent_id     = coder_agent.main.id
  slug         = "code-server"
  display_name = "VS Code"
  # code-server is NOT installed by the workspace image (Coder
  # provisions an IDE per the team's policy). When code-server IS
  # present on the agent, it listens on 13337 by default.
  url          = "http://localhost:13337/?folder=/home/coder/stave"
  icon         = "/icon/code.svg"
  subdomain    = false
  share        = "owner"

  healthcheck {
    url       = "http://localhost:13337/healthz"
    interval  = 10
    threshold = 6
  }
}

resource "coder_app" "terminal" {
  agent_id     = coder_agent.main.id
  slug         = "terminal"
  display_name = "Terminal"
  command      = "bash -l"
  icon         = "/icon/terminal.svg"
  share        = "owner"
}

# ─── Docker image + container ────────────────────────────────────────

resource "docker_image" "stave" {
  # Tag tracks the workspace name so the image is pinned per-create.
  name = "stave-workspace:${data.coder_workspace.me.id}"

  build {
    # Context is the stave module root (one level above this file)
    # because the Dockerfile COPYs controls/, chains/, examples/,
    # etc. from there.
    context    = "../"
    dockerfile = "stave-workspace/Dockerfile"
    # Avoid stale layers on `coder build` reruns.
    no_cache   = false
  }

  # Cache busts when the Dockerfile, .dockerignore, or anything the
  # Dockerfile COPYs from the build context changes. This list maps
  # to the Dockerfile's COPY directives — keep them in sync.
  triggers = {
    dockerfile   = filemd5("${path.module}/Dockerfile")
    dockerignore = filemd5("${path.module}/.dockerignore")
    motd         = filemd5("${path.module}/motd.sh")
    start_here   = filemd5("${path.module}/../docs/workflows/START-HERE.md")
  }

  keep_locally = true
}

resource "docker_volume" "home" {
  name = "coder-${data.coder_workspace.me.id}-home"
}

resource "docker_container" "workspace" {
  count    = data.coder_workspace.me.start_count
  image    = docker_image.stave.image_id
  name     = "coder-${data.coder_workspace_owner.me.name}-${data.coder_workspace.me.name}"
  hostname = data.coder_workspace.me.name

  env = [
    "CODER_AGENT_TOKEN=${coder_agent.main.token}",
  ]

  entrypoint = ["sh", "-c", coder_agent.main.init_script]

  # Persist /home/coder across restarts — adopters' notes, their
  # cloned repo, their snapshot dirs survive workspace stop/start.
  volumes {
    container_path = "/home/coder"
    volume_name    = docker_volume.home.name
    read_only      = false
  }

  # The Coder agent expects to reach Coder over the network — host
  # mode is the simplest setup that works with Coder OSS on a
  # single-host install. Premium installs may swap this for a more
  # restrictive network resource; the variable kept here makes that
  # a one-line change.
  network_mode = "bridge"
}
