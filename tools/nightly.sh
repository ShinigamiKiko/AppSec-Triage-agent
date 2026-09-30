#!/usr/bin/env bash

set -u -o pipefail

cd "$(dirname "$0")/.." || exit 1

PROVIDER="${PROVIDER:-deepseek}"
OUT_ROOT="${OUT_ROOT:-out/nightly}"
WORKERS="${WORKERS:-4}"
export PHPACTOR_PHAR="${PHPACTOR_PHAR:-$HOME/phpactor.phar}"

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  echo "usage: $0 <repo> [repo...]" >&2
  exit 2
fi

mkdir -p "$OUT_ROOT"

python3 -m appsec_triage.cli doctor >"$OUT_ROOT/doctor.log" 2>&1
if ! python3 -m appsec_triage.cli providers | grep -q "^$PROVIDER .*\(key set\|no key needed\)"; then
  echo "error: provider '$PROVIDER' is not usable — see $OUT_ROOT/doctor.log" >&2
  python3 -m appsec_triage.cli providers | grep "^$PROVIDER" >&2
  exit 2
fi

failed=0
for target in "${targets[@]}"; do
  name=$(basename "$target")
  out="$OUT_ROOT/$name"
  log="$out/run.log"
  mkdir -p "$out"

  echo "=== $name  $(date '+%F %T')"
  if python3 -m appsec_triage.cli run "$target" \
      -p "$PROVIDER" -o "$out" --workers "$WORKERS" >"$log" 2>&1; then
    verdicts="$out/verdicts-$PROVIDER.jsonl"
    if [ -f "$verdicts" ]; then
      python3 -m appsec_triage.cli queue "$verdicts" -f "$out/scans" \
        -o "$out/queue.json" >>"$log" 2>&1
      tail -c 400 "$log" | tr '\r' '\n' | tail -3
    fi
  else
    failed=$((failed + 1))
    echo "  ! $name failed — see $log" >&2
    tail -5 "$log" >&2
  fi
done

echo "=== done $(date '+%F %T'); $failed project(s) failed"
exit "$failed"
