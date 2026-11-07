#!/usr/bin/env bash
# Reproduce data/corpus.sqlite from source. Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p vendor data

if [ ! -d vendor/DeFiHackLabs/.git ]; then
  echo ">> cloning DeFiHackLabs (shallow, no submodules)"
  git clone --depth 1 --no-recurse-submodules \
    https://github.com/SunWeb3Sec/DeFiHackLabs.git vendor/DeFiHackLabs
else
  echo ">> updating DeFiHackLabs"
  git -C vendor/DeFiHackLabs pull --ff-only || true
fi

echo ">> ingesting"
rm -f data/corpus.sqlite
python3 cli.py ingest defihacklabs
python3 cli.py stats
