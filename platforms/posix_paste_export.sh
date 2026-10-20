#!/bin/sh
# Encode a native evidence directory for SecureCRT / 4A / bastion paste transfer.
# No Python required. Output is text only; paste into maintenance host and run paste-import.
set -u
SRC=${1:-}
if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
  echo "Usage: sh platforms/posix_paste_export.sh <evidence-directory>" >&2
  exit 2
fi
case $SRC in /*) ;; *) SRC="$PWD/$SRC" ;; esac
if [ -L "$SRC" ]; then
  echo "Refusing symbolic-link evidence root." >&2
  exit 2
fi
# Prefer GNU/BusyBox tools; fall back carefully.
ENCODE= 
if command -v openssl >/dev/null 2>&1; then
  ENCODE="openssl base64"
elif command -v base64 >/dev/null 2>&1; then
  ENCODE="base64"
else
  echo "Neither openssl nor base64 is available." >&2
  exit 127
fi
TMP=${TMPDIR:-/tmp}/pc-insp-paste-$$
trap 'rm -f "$TMP.tar" "$TMP.gz" "$TMP.b64" "$TMP.sha" 2>/dev/null || :' EXIT HUP INT TERM
# Portable tar of regular files only at top level.
(
  CDPATH= cd "$SRC" || exit 2
  # shellcheck disable=SC2035
  tar cf "$TMP.tar" . 2>/dev/null || tar -cf "$TMP.tar" . || exit 2
)
gzip -c "$TMP.tar" >"$TMP.gz" || exit 2
if command -v sha256sum >/dev/null 2>&1; then
  SHA=$(sha256sum "$TMP.gz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  SHA=$(shasum -a 256 "$TMP.gz" | awk '{print $1}')
elif command -v openssl >/dev/null 2>&1; then
  SHA=$(openssl dgst -sha256 "$TMP.gz" | awk '{print $NF}')
else
  SHA=unavailable
fi
BYTES=$(wc -c <"$TMP.gz" | tr -d ' ')
$ENCODE <"$TMP.gz" >"$TMP.b64" || exit 2
# Split into numbered chunks for terminal paste reliability.
LINES=$(wc -l <"$TMP.b64" | tr -d ' ')
CHUNK_LINES=40
TOTAL=$(( (LINES + CHUNK_LINES - 1) / CHUNK_LINES ))
if [ "$TOTAL" -lt 1 ]; then TOTAL=1; fi
# dash/busybox printf treats a format that begins with "-" as options; always use %s.
printf '%s\n' '-----BEGIN PC-INSPECTION-PASTE-----'
printf '%s\n' 'format=1'
printf '%s\n' 'encoding=gzip-tar-base64'
printf '%s\n' "payload_sha256=$SHA"
printf '%s\n' "payload_bytes=$BYTES"
printf '%s\n' "chunks=$TOTAL"
printf '%s\n' 'note=Paste the entire block into the maintenance host. Import is parse-only.'
n=1
start=1
while [ "$n" -le "$TOTAL" ]; do
  end=$((start + CHUNK_LINES - 1))
  printf '%s\n' "-----CHUNK $n/$TOTAL-----"
  sed -n "${start},${end}p" "$TMP.b64"
  start=$((end + 1))
  n=$((n + 1))
done
printf '%s\n' '-----END PC-INSPECTION-PASTE-----'
exit 0
