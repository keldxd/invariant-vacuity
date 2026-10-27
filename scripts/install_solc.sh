#!/usr/bin/env bash
# Installs the solc versions the fixtures pin into ~/.svm, where Forge looks for them,
# so the fixtures can run with `offline = true`.
set -euo pipefail
for v in 0.8.0 0.8.4 0.8.7 0.8.13 0.8.19 0.8.24 0.8.28; do
  dst="$HOME/.svm/$v/solc-$v"
  [ -x "$dst" ] && continue
  mkdir -p "$(dirname "$dst")"
  curl -sSfL -o "$dst" "https://github.com/ethereum/solidity/releases/download/v$v/solc-static-linux"
  chmod +x "$dst"
done
