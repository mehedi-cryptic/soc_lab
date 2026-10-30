#!/usr/bin/env bash
# Regenerate SIEM queries from the Sigma rules.
#   Splunk SPL   -> detections/queries/splunk/*.spl
#   Elastic      -> detections/queries/elastic/*.lucene  (correlation rules -> *.esql)
#
# Requirements: pip install sigma-cli && sigma plugin install splunk elasticsearch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="$ROOT/detections/sigma"
SPL="$ROOT/detections/queries/splunk"
ES="$ROOT/detections/queries/elastic"
mkdir -p "$SPL" "$ES"

for rule in "$RULES"/*.yml; do
  name="$(basename "$rule" .yml)"
  echo "[*] $name"
  sigma convert -t splunk -p splunk_windows "$rule" 2>/dev/null | grep -v '^Parsing' > "$SPL/$name.spl"

  if grep -q '^correlation:' "$rule"; then
    # Lucene cannot aggregate, so correlation rules become ES|QL
    sigma convert -t esql -p ecs_windows --disable-pipeline-check "$rule" 2>/dev/null \
      | grep -v '^Parsing' > "$ES/$name.esql"
  else
    sigma convert -t lucene -p ecs_windows "$rule" 2>/dev/null | grep -v '^Parsing' > "$ES/$name.lucene"
  fi
done
echo "[+] Done. $(ls "$SPL" | wc -l) Splunk and $(ls "$ES" | wc -l) Elastic queries."
