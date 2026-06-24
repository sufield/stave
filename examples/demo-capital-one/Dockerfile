# Capital One demo — Demo B (Soufflé + Z3 reachability proof), preinstalled.
#
# Demo B is pure souffle + z3 + bash/awk — no Go, no stave binary. This image
# bundles those tools and the reasoning spec so the proof runs anywhere Docker
# does, without installing anything on the host.
#
# Build (context = the stave/ repo root, so the reasoning spec is in scope):
#     cd stave
#     docker build -f examples/demo-capital-one/Dockerfile -t stave-capone-demo .
#
# Run:
#     docker run --rm stave-capone-demo            # runs the proof
#     docker run --rm stave-capone-demo verify     # proof + diff against expected
#
FROM ubuntu:22.04

# z3 (SMT) is in the base universe repo; souffle (Datalog) comes from the
# official Soufflé apt repo (it was dropped from Ubuntu's own repos). 22.04
# (jammy) is the newest release the Soufflé repo publishes packages for.
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget gnupg ca-certificates z3 gawk bash diffutils \
 && wget -qO- https://souffle-lang.github.io/ppa/souffle-key.public \
      | gpg --dearmor -o /usr/share/keyrings/souffle.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/souffle.gpg] https://souffle-lang.github.io/ppa/ubuntu/ stable main" \
      > /etc/apt/sources.list.d/souffle.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends souffle \
 && rm -rf /var/lib/apt/lists/* \
 && souffle --version | grep -i version \
 && z3 --version

WORKDIR /demo
# The reasoning spec that computes/proves the reaches_sensitive signal.
COPY examples/iam-foothold-internet-reach/ ./iam-foothold-internet-reach/
COPY examples/demo-capital-one/docker-entrypoint.sh /usr/local/bin/demo
RUN chmod +x /usr/local/bin/demo ./iam-foothold-internet-reach/run.sh

ENTRYPOINT ["/usr/local/bin/demo"]
