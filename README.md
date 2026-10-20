# keyshape

A small, dependency-free CLI that scans a codebase for secret-shaped strings
(API keys, tokens, private keys, high-entropy credentials) and reports them
with file, line, and a redacted snippet. Built for CI: exits non-zero when
findings exist.

## Features

- Pattern-based detection for common secret formats (AWS, GitHub, Slack, Google,
  Stripe, JWT, private key blocks, generic password/secret assignments).
- Inline allowlisting via `keyshape:ignore` comments.
- `.keyshapeignore` file support (glob patterns).
- Text or JSON output.
- No external dependencies — pure Python 3.9+.
- Skips binary files, lockfiles, and large files by default.

## Install

No dependencies. Clone or copy the `keyshape/` directory.

```bash
cd keyshape
```

## Usage

```bash
# scan current directory
python keyshape.py .

# JSON output for CI
python keyshape.py ./src --format json

# don't fail the build (report only)
python keyshape.py . --no-fail

# ignore specific paths
echo "tests/fixtures/**" > .keyshapeignore
```

Inline allowlist:

```python
API_KEY = "abc123..."  # keyshape:ignore
```

## Exit codes

- `0` — no findings (or `--no-fail`).
- `1` — findings detected.
- `2` — usage error.

## License

MIT
