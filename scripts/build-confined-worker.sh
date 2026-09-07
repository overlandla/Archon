#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
worker_build_source=packages/paths/src/bundled-build.ts
worker_build_backup=$(mktemp)
cp "$worker_build_source" "$worker_build_backup"
restore_worker_build() {
  cp "$worker_build_backup" "$worker_build_source"
  rm "$worker_build_backup"
}
trap restore_worker_build EXIT
worker_build_commit=$(git rev-parse HEAD)
cat > "$worker_build_source" <<EOF
export const BUNDLED_IS_BINARY = true;
export const BUNDLED_VERSION = '0.10.0-confined-experimental';
export const BUNDLED_GIT_COMMIT = '$worker_build_commit';
export const BUNDLED_WEB_DIST_SHA256 = '';
EOF
bun build --compile scripts/confined-workflow.ts --outfile "${1:?output binary required}"
