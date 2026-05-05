Stave Z3 Solver
===============

Z3-backed solver for the Stave Intermediate Representation (SIR).
Consumes SIR JSON via stdin, emits Stave-format findings via stdout.

## Usage

```
cat fixture.sir.json | python -m stave_solver.main
```

## Contract

- **stdin**: SIR JSON document (one document per invocation).
- **stdout**: a JSON array of Stave Finding objects. Empty array
  means "no violations found"; this is the Iter 3.1.1 baseline
  behavior — actual Z3 logic lands in 3.1.2.
- **stderr**: a JSON object with a `"error"` key when parsing or
  solving fails.
- **exit codes**:
  - `0`: success (findings produced; may be empty).
  - `2`: input parse error or other user-correctable failure.

## Integration

The Stave Go binary invokes this solver as a subprocess via
`STAVE_SHADOW_CMD`:

```
STAVE_SHADOW_CMD="python -m stave_solver.main" stave apply ...
```

Iter 3.1.4 wires the subprocess bridge in
`internal/adapters/evaluation/external/python_source.go`.

## Development

```
pip install -r requirements.txt
pip install -e .
pytest tests/
```
