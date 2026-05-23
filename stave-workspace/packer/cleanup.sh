#!/bin/bash
# DigitalOcean marketplace image cleanup.
#
# Mirrors the canonical cleanup steps in
# https://github.com/digitalocean/marketplace-partners (see also the
# img_check.sh validator the Packer template runs before this script).
# Anything sensitive or build-host-specific must NOT survive into the
# snapshot — image validation will reject a build that ships the
# build droplet's SSH keys, bash history, machine-id, or logs.

set -uo pipefail

echo "── Sanity-check the binaries before clearing logs ──────────"
stave version
stave-mcp --help 2>&1 | head -1 || true
steampipe --version
# `stave features` exercises the embedded catalog + predicate engine.
# If it errors, the image is broken — fail loudly so the build aborts
# before snapshot.
stave features >/dev/null

echo "── Clear logs ──────────────────────────────────────────────"
find /var/log -type f \( -name '*.log' -o -name '*.gz' -o -name 'lastlog' -o -name 'wtmp' -o -name 'btmp' \) -exec truncate -s 0 {} \;
rm -rf /var/log/journal/* || true

echo "── Clear temp + apt caches ─────────────────────────────────"
rm -rf /tmp/* /var/tmp/* /var/cache/apt/archives/*.deb || true
apt-get -y autoremove
apt-get -y autoclean
apt-get -y clean

echo "── Reset machine-id (regenerated on first boot) ────────────"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

echo "── Remove build-droplet SSH keys + host keys ───────────────"
# Host keys MUST be regenerated on first boot of a new droplet —
# otherwise every droplet from this image shares the same keys.
# Removing them triggers regen via openssh-server's first-boot
# postinst hook on Ubuntu cloud-init builds.
rm -f /etc/ssh/ssh_host_*
rm -rf /root/.ssh /home/*/.ssh 2>/dev/null || true

echo "── Clear shell history + cloud-init state ──────────────────"
rm -f /root/.bash_history /home/*/.bash_history 2>/dev/null || true
rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance 2>/dev/null || true
history -c || true

echo "── Final disk-usage report ─────────────────────────────────"
df -h /
du -sh /opt/stave /usr/local/bin/stave /usr/local/bin/stave-mcp /usr/local/go || true
