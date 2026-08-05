#!/usr/bin/env bash
#
# Unattended run over a list of repositories: scan, triage, review queue.
#
# Written to survive being left alone. Each project is independent — one failing
# does not stop the rest — and an interrupted triage is resumed from its journal
# on the next invocation rather than paid for twice. Safe to re-run at any time;
# safe to kill at any time.
#
#   tools/nightly.sh /path/to/repo-a /path/to/repo-b
#   PROVIDER=ollama tools/nightly.sh /path/to/repo    # keep it in the perimeter
#
# Exit code is the number of projects that failed, so a scheduler can alert on
# it without parsing the log.

set -u -o pipefail

cd "$(dirname "$0")/.." || exit 1

PROVIDER="${PROVIDER:-deepseek}"
OUT_ROOT="${OUT_ROOT:-out/nightly}"
WORKERS="${WORKERS:-4}"
# Only set when it is not already on PATH; the launcher is read from lsp.yaml.
export PHPACTOR_PHAR="${PHPACTOR_PHAR:-$HOME/phpactor.phar}"

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  echo "usage: $0 <repo> [repo...]" >&2
  exit 2
fi

mkdir -p "$OUT_ROOT"

# Fail before spending anything. A missing API key is worth learning in the
# first second, not on finding 300 of an overnight run. `doctor` reports on
# every configured provider, including ones this run will not touch, so the
# gate is on the chosen provider alone.
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
  # Logged to a file rather than piped: a pipe loses whatever it is still
  # buffering when the process dies, which is exactly when the log matters.
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
