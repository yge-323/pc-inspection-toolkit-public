#!/bin/sh
# POSIX-only evidence capture for RHEL 5/6, CentOS 6/7+, Ubuntu, openEuler, macOS.
# Run manually in an already-authorized scope. No Python, jq, or install required.
set -u
SCRIPT_PATH=$0
case $SCRIPT_PATH in /*) ;; *) SCRIPT_PATH="$PWD/$SCRIPT_PATH" ;; esac
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$SCRIPT_PATH")" && pwd)
OUT=${1:-"$SCRIPT_DIR/../data/raw/inspection-evidence"}
umask 077
if [ -e "$OUT" ]; then echo "Refusing to reuse existing output path." >&2; exit 2; fi
mkdir -p "$OUT" || exit 2
STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || :)
if [ -z "$STARTED_AT" ]; then STARTED_AT=unknown; fi
{
  printf 'started_at=%s\n' "$STARTED_AT"
  printf '%s\n' 'timezone=UTC' 'privilege=unknown' 'collector_version=0.3.0-landable'
  printf '%s\n' 'command_catalog=os,os_release,architecture,uptime,cpu_count,memory_summary,graphics_summary,disks,listeners,firewall,startup_items,services,privilege,accounts,security_status,packages_security'
} >"$OUT/collection_metadata.txt"
printf '%s\n' 0 >"$OUT/collection_metadata.exit-code.txt"
if command -v perl >/dev/null 2>&1 && [ -r "$SCRIPT_DIR/bounded_exec.pl" ]; then
  BOUNDED=1
else
  BOUNDED=0
fi
run_capture() {
  name=$1; shift
  rc=0
  if [ "$BOUNDED" -eq 1 ] && command -v "$1" >/dev/null 2>&1; then
    (ulimit -f 4096 2>/dev/null || :; perl "$SCRIPT_DIR/bounded_exec.pl" 20 2097152 "$OUT/$name.txt" -- "$@")
    rc=$?
    printf '%s\n' "$rc" >"$OUT/$name.exit-code.txt"
  else
    if [ "$BOUNDED" -eq 0 ]; then
      printf '%s\n' 'COLLECTOR_STATUS=NOT_CHECKED_TIMEOUT_ISOLATION_UNAVAILABLE' >"$OUT/$name.txt"
      printf '%s\n' 126 >"$OUT/$name.exit-code.txt"
      rc=126
    else
      printf '%s\n' "COLLECTOR_STATUS=TOOL_UNAVAILABLE:$1" >"$OUT/$name.txt"
      printf '%s\n' 127 >"$OUT/$name.exit-code.txt"
      rc=127
    fi
  fi
  if [ "$rc" -ne 0 ] 2>/dev/null || grep -q '^COLLECTOR_STATUS=' "$OUT/$name.txt" 2>/dev/null; then
    CAPTURE_FAILED=1
  fi
}
CAPTURE_FAILED=0
run_capture os uname -a
run_capture os_release sh -c 'test -r /etc/os-release && cat /etc/os-release || (test -r /etc/redhat-release && cat /etc/redhat-release || sw_vers 2>/dev/null)'
run_capture architecture uname -m
run_capture uptime uptime
run_capture cpu_count getconf _NPROCESSORS_ONLN
run_capture memory_summary sh -c 'if test -r /proc/meminfo; then awk "/^MemTotal:/ {print \"MemTotal_kB=\" \$2}" /proc/meminfo; elif command -v sysctl >/dev/null 2>&1; then sysctl -n hw.memsize; else echo COLLECTOR_STATUS=NOT_CHECKED_MEMORY; fi'
run_capture graphics_summary sh -c 'if command -v lspci >/dev/null 2>&1; then lspci -mm | awk -F"\"" "/VGA compatible controller|3D controller|Display controller/ {print \$4, \$6}"; elif command -v system_profiler >/dev/null 2>&1; then echo COLLECTOR_STATUS=NOT_CHECKED_GRAPHICS_MODEL_PRIVACY; else echo COLLECTOR_STATUS=NOT_CHECKED_GRAPHICS_TOOL_UNAVAILABLE; fi'
run_capture disks df -Pk /
# Prefer listen-only ss; fall back to full netstat (analyzer skips non-listen rows).
run_capture listeners sh -c 'if command -v ss >/dev/null 2>&1; then ss -tuln 2>/dev/null || ss -an; elif command -v netstat >/dev/null 2>&1; then netstat -an; else echo COLLECTOR_STATUS=TOOL_UNAVAILABLE:ss_or_netstat; exit 127; fi'
run_capture firewall sh -c 'if command -v nft >/dev/null 2>&1; then nft list ruleset; elif command -v iptables >/dev/null 2>&1; then iptables -S; elif command -v pfctl >/dev/null 2>&1; then pfctl -s info; else echo COLLECTOR_STATUS=NOT_CHECKED_FIREWALL; fi'
run_capture startup_items sh -c 'found=0; for f in /etc/rc[0-6].d/S*; do if test -e "$f"; then basename "$f"; found=1; fi; done; if command -v systemctl >/dev/null 2>&1; then systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | awk "{print \$1}" | head -n 200; found=1; fi; test "$found" -eq 1 || echo COLLECTOR_STATUS=NOT_CHECKED_STARTUP_ITEMS'
run_capture services sh -c '
if command -v systemctl >/dev/null 2>&1; then
  out=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || true)
  if test -n "$out"; then printf "%s\n" "$out"; else echo COLLECTOR_STATUS=NOT_CHECKED_SERVICES; fi
elif command -v chkconfig >/dev/null 2>&1; then
  chkconfig --list
else
  echo COLLECTOR_STATUS=NOT_CHECKED_SERVICES
fi
'
run_capture privilege sh -c 'id -u'
# Privacy-safe account summary: counts and flags only, never usernames or password hashes.
run_capture accounts sh -c '
uid0=0; total=0; empty_pw=0; nologin=0
if test -r /etc/passwd; then
  while IFS=: read -r name pw uid gid gecos home shell; do
    total=$((total+1))
    if test "$uid" = "0"; then uid0=$((uid0+1)); fi
    case $shell in */nologin|*/false) nologin=$((nologin+1));; esac
  done < /etc/passwd
fi
if test -r /etc/shadow; then
  while IFS=: read -r name hash rest; do
    if test -z "$hash"; then empty_pw=$((empty_pw+1)); fi
  done < /etc/shadow
  shadow_readable=yes
else
  shadow_readable=no
fi
printf "TOTAL_ACCOUNTS=%s\n" "$total"
printf "UID0_COUNT=%s\n" "$uid0"
printf "NOLOGIN_SHELL_COUNT=%s\n" "$nologin"
printf "EMPTY_PASSWORD_COUNT=%s\n" "$empty_pw"
printf "SHADOW_READABLE=%s\n" "$shadow_readable"
printf "ACCOUNT_NAMES_EXPORTED=no\n"
printf "PASSWORD_HASHES_EXPORTED=no\n"
'
# Security summary: login.defs + selected sshd_config keys (no secrets).
# Emit KEY=value facts only — never COLLECTOR_STATUS=SUMMARY (seal/import rejects unknown markers).
run_capture security_status sh -c '
if test -r /etc/login.defs; then
  awk "/^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD)[[:space:]]+/ {print \$1 \"=\" \$2}" /etc/login.defs
else
  printf "LOGIN_DEFS=not_readable\n"
fi
sshd=""
for c in /etc/ssh/sshd_config /etc/sshd_config; do
  if test -r "$c"; then sshd=$c; break; fi
done
if test -n "$sshd"; then
  printf "SSHD_CONFIG_SOURCE=present\n"
  awk "
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*PermitRootLogin[[:space:]]+/ { print \"SSH_PERMIT_ROOT_LOGIN=\" \$2 }
    /^[[:space:]]*PasswordAuthentication[[:space:]]+/ { print \"SSH_PASSWORD_AUTHENTICATION=\" \$2 }
    /^[[:space:]]*PermitEmptyPasswords[[:space:]]+/ { print \"SSH_PERMIT_EMPTY_PASSWORDS=\" \$2 }
    /^[[:space:]]*Protocol[[:space:]]+/ { print \"SSH_PROTOCOL=\" \$2 }
    /^[[:space:]]*PubkeyAuthentication[[:space:]]+/ { print \"SSH_PUBKEY_AUTHENTICATION=\" \$2 }
  " "$sshd"
else
  printf "SSHD_CONFIG_SOURCE=not_readable\n"
fi
for c in firewalld iptables nft pfctl; do
  if command -v "$c" >/dev/null 2>&1; then printf "FIREWALL_TOOL_AVAILABLE=%s\n" "$c"; fi
done
'
run_capture packages_security sh -c '
out=""
if command -v rpm >/dev/null 2>&1; then
  out=$(rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE}\n" kernel openssl openssh-server 2>/dev/null || true)
elif command -v dpkg-query >/dev/null 2>&1; then
  out=$(dpkg-query -W -f="\${Package} \${Version}\n" openssh-server openssl 2>/dev/null || true)
else
  echo COLLECTOR_STATUS=NOT_CHECKED_SECURITY_PACKAGES
  exit 0
fi
if test -n "$out"; then printf "%s\n" "$out"; else echo COLLECTOR_STATUS=NOT_CHECKED_SECURITY_PACKAGES; fi
'
FINISHED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || :)
if [ -z "$FINISHED_AT" ]; then FINISHED_AT=unknown; fi
printf 'finished_at=%s\n' "$FINISHED_AT" >>"$OUT/collection_metadata.txt"
# Refresh privilege metadata from captured UID when available.
if test -r "$OUT/privilege.txt"; then
  UID_VAL=$(head -n 1 "$OUT/privilege.txt" 2>/dev/null || :)
  case $UID_VAL in
    0) PRIV=root ;;
    ''|*[!0-9]*) PRIV=unknown ;;
    *) PRIV=ordinary ;;
  esac
  tmp=$OUT/collection_metadata.txt.tmp
  awk -v priv="$PRIV" 'BEGIN{FS=OFS="="} $1=="privilege"{$2=priv} {print}' "$OUT/collection_metadata.txt" >"$tmp" && mv "$tmp" "$OUT/collection_metadata.txt"
fi
printf '%s\n' 'Capture finished. Review individual statuses before sealing or transfer.'
printf '%s\n' 'Tip: encode for bastion paste with: sh platforms/posix_paste_export.sh '"$OUT"
if [ "$CAPTURE_FAILED" -eq 1 ]; then exit 4; fi
exit 0
