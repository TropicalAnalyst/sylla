#!/usr/bin/env bash
set -euo pipefail

if [ -f .env ]; then
  echo ".env already exists. Skipping generation."
  exit 0
fi

if [ ! -f env.example ]; then
  echo "env.example not found. Aborting."
  exit 1
fi

python3 - <<'PY'
import secrets
from pathlib import Path

src = Path('env.example')
dst = Path('.env')
secret = secrets.token_hex(32)

lines = src.read_text().splitlines(True)
found = False
out_lines = []
for line in lines:
    if line.startswith('SECRET_KEY='):
        out_lines.append(f'SECRET_KEY={secret}\n')
        found = True
    else:
        out_lines.append(line)

if not found:
    out_lines.append(f'\nSECRET_KEY={secret}\n')

dst.write_text(''.join(out_lines))
print(f"Created {dst} with a strong SECRET_KEY.")
PY

echo "Done. Review .env and adjust other values as needed."

