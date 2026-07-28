# pre-commit

Run stave validation before every git commit.

## Prerequisites

- Ubuntu 24
- Python 3 (for pre-commit)
- stave binary installed

## Install

```bash
# Install pre-commit
pip install pre-commit

# Install stave
git clone https://github.com/sufield/stave.git /tmp/stave
cd /tmp/stave && make build
sudo cp /tmp/stave/stave /usr/local/bin/
```

Add the hook configuration to your project:

```bash
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: local
    hooks:
      - id: stave-validate
        name: stave validate
        entry: stave validate --controls controls --observations observations --strict
        language: system
        pass_filenames: false
        always_run: true
EOF
```

Install the hook:

```bash
pre-commit install
```

## Run

```bash
# Make a change and commit
echo "test" >> observations/notes.txt
git add .
git commit -m "test change"
```

Stave runs automatically before the commit. If validation fails
(malformed observations, missing required fields), the commit is
blocked with the specific error.

## What you see

```
stave validate...........................................................Failed
- hook id: stave-validate
- exit code: 2

[ERR] Input validation failed
  Message: no snapshots in observations (expected .json files with schema_version: obs.v0.1)
```

Fix the issue, `git add`, and commit again.
