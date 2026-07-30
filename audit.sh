#!/usr/bin/env bash
# malware-audit: threat sweep for a source tree/git repo OR a compiled binary.
# Usage: audit.sh [TARGET]   (default: current dir)
#   TARGET is a directory  -> source/repo sweep (greps + optional scanners)
#   TARGET is a file       -> binary analysis (libs, imports, strings, packing)
#   TARGET is a git URL    -> shallow clone to a temp dir, sweep, delete
# Each section prints hits; YOU read them in context — a match is a lead, not a
# verdict. Most hits are legitimate.
# Exit: 0 = no high-signal patterns matched, 1 = SUSPICIOUS (triage only), 2 = bad args.
set -uo pipefail

TARGET="${1:-.}"

# A git URL is cloned and then swept exactly like any other directory — the only
# thing a remote repo needs is a checkout. "$TARGET" is untrusted, so it must not
# be able to act as anything but a URL: `--` stops it being read as an option
# (-u/--upload-pack runs a command) and the ext helper is disabled outright,
# since `git clone ext::sh -c id` is remote code execution and this script's one
# promise is that it does not execute repo code.
case "$TARGET" in
  git://*|http://*|https://*|git@*|ssh://*)
    CLONE=$(mktemp -d -t audit-clone-XXXXXX) || exit 2
    trap 'rm -rf "$CLONE"' EXIT
    echo "Cloning $TARGET"
    git -c protocol.ext.allow=never -c protocol.file.allow=user \
        clone --quiet --depth=200 -- "$TARGET" "$CLONE/src" || {
          echo "clone failed: $TARGET" >&2; exit 2; }
    TARGET="$CLONE/src"
    ;;
esac
EXCLUDES=(--exclude-dir=.git --exclude-dir=target --exclude-dir=node_modules
          --exclude-dir=dist --exclude-dir=build --exclude-dir=vendor
          --exclude-dir=.venv --exclude-dir=venv --exclude-dir=__pycache__
          # ponytail: skip prose/lockfiles — they bury code hits in doc URLs.
          # CI (.yml) and install (.sh) scripts stay in scope for §8.
          --exclude=*.md --exclude=*.lock --exclude=LICENSE* --exclude=*.txt)

g() { grep -rniE "${EXCLUDES[@]}" "$1" "$TARGET" 2>/dev/null; }
section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

# ── Binary analysis ─────────────────────────────────────────────────
# Same commands used to vet a compiled ELF/PE/Mach-O by hand. Facts (libs,
# imports, URLs) are informational — tons of legit binaries have them. Only
# genuine tamper signals are scored: packing, appended payload, C2 strings.
audit_binary() {
  local F="$1" HIGH=0 size tailn
  size=$(stat -c%s "$F" 2>/dev/null || stat -f%z "$F" 2>/dev/null || echo 0)
  section "BINARY: $F"
  file "$F"
  command -v sha256sum >/dev/null && echo "sha256: $(sha256sum "$F" | awk '{print $1}')"

  section "B1. LINKED LIBRARIES (unexpected net/crypto libs worth a look)"
  readelf -d "$F" 2>/dev/null | grep NEEDED || echo "  (not dynamic ELF / no NEEDED entries)"

  section "B2. IMPORTED FUNCTIONS — network / exec / destructive / dynamic-load"
  nm -D "$F" 2>/dev/null | grep -iE \
    'socket|connect|getaddrinfo|gethostby|bind|listen|send|recv|dlopen|dlsym|execve|system|popen|fork|unlink|remove|ptrace|mprotect' \
    || echo "  (none, or stripped/static dynamic table)"

  section "B3. EMBEDDED URLs / HOSTS / IPs (informational)"
  strings -n 6 "$F" | grep -iE 'https?://|([0-9]{1,3}\.){3}[0-9]{1,3}|[a-z0-9.-]+\.onion' \
    | grep -viE 'GLIBC|\.so\.[0-9]|gnu\.org|w3\.org|schemas' | sort -u | head -40 \
    || echo "  (none)"

  section "BINARY TRIAGE (tamper signals — scored)"
  # Packing/obfuscation: UPX magic, or almost no printable strings in a big file.
  if grep -aqE 'UPX!|\$Info: This file is packed' "$F"; then
    printf '  \033[1;31m⚠ %-24s\033[0m\n' "packed (UPX)"; HIGH=$((HIGH+1))
  fi
  # Appended payload after the ELF section-header table (self-extractor trick).
  if readelf -h "$F" >/dev/null 2>&1; then
    local shoff shent shnum end
    shoff=$(readelf -h "$F" | awk -F: '/Start of section headers/{gsub(/[^0-9]/,"",$2);print $2}')
    shent=$(readelf -h "$F" | awk -F: '/Size of section headers/{gsub(/[^0-9]/,"",$2);print $2}')
    shnum=$(readelf -h "$F" | awk -F: '/Number of section headers/{gsub(/[^0-9]/,"",$2);print $2}')
    if [ -n "${shoff:-}" ] && [ -n "${shent:-}" ] && [ -n "${shnum:-}" ]; then
      end=$((shoff + shent*shnum))
      if [ $((size - end)) -gt 4096 ]; then
        printf '  \033[1;31m⚠ %-24s\033[0m %d bytes after section headers\n' "appended data" $((size-end))
        HIGH=$((HIGH+1))
      fi
    fi
  fi
  # Also check the tail for archive magic (zip/7z/xz) appended to the file.
  # Cap byte count to the file size — some `tail` builds (uutils) error on -c
  # larger than the file. ponytail: 256K tail window is plenty for a trailer.
  tailn=$(( size < 262144 ? size : 262144 )); [ "$tailn" -gt 0 ] || tailn=1
  if tail -c "$tailn" "$F" 2>/dev/null | grep -aqE 'PK\x03\x04|7z\xbc\xaf|\xfd7zXZ'; then
    printf '  \033[1;31m⚠ %-24s\033[0m\n' "embedded archive magic"; HIGH=$((HIGH+1))
  fi
  # C2 / pipe-to-shell strings baked into the binary.
  for pat in '\.onion' 'pastebin\.com' 'discord.*webhook' 't\.me/' 'curl[^|]*\|[^|]*sh'; do
    if strings -n 6 "$F" | grep -qaiE "$pat"; then
      printf '  \033[1;31m⚠ %-24s\033[0m matches /%s/\n' "C2/pipe-to-shell string" "$pat"; HIGH=$((HIGH+1))
    fi
  done

  printf '\n\033[1m── VERDICT ──\033[0m\n'
  if [ "$HIGH" -gt 0 ]; then
    printf '\033[1;31mSUSPICIOUS\033[0m — %d tamper signal(s). Manual review REQUIRED.\n' "$HIGH"
    return 1
  fi
  printf '\033[1;32mNO TAMPER SIGNALS\033[0m — but NOT a clean bill. A stripped binary\n'
  printf 'cannot be proven benign statically. Review B1–B3 above, and verify the\n'
  printf 'sha256 against an official published checksum for real assurance.\n'
  return 0
}

# ── Dispatch: binary file vs directory ──────────────────────────────
if [ -f "$TARGET" ] && [ ! -d "$TARGET" ]; then
  audit_binary "$TARGET"; exit $?
fi
[ -d "$TARGET" ] || { echo "not a file or directory: $TARGET" >&2; exit 2; }
echo "Auditing: $(cd "$TARGET" && pwd)"

section "0. RECON — manifests & install hooks (read these fully)"
find "$TARGET" \( -name build.rs -o -name setup.py -o -name Makefile \
   -o -name Cargo.toml -o -name package.json -o -name pyproject.toml \
   -o -name go.mod \) \
   -not -path '*/.git/*' -not -path '*/target/*' -not -path '*/node_modules/*' 2>/dev/null
echo "-- npm install hooks (postinstall/preinstall are the #1 supply-chain vector):"
g '"(pre|post)install"|scripts"[[:space:]]*:'

section "1. NETWORK / EXFILTRATION — hardcoded vs dynamic endpoint? sends data?"
g 'TcpStream|TcpListener|UdpSocket|reqwest|hyper|requests\.|urllib|fetch\(|axios|net\.Dial|http://|https://|/dev/tcp|getaddrinfo|webhook|\.send\('

section "2. CREDENTIAL / SECRET HARVESTING — plumbing vs enumerating secrets?"
g 'env::var|getenv|os\.environ|process\.env|SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL|\.aws|\.ssh|keychain|\.npmrc|\.git-credentials'

section "3. DESTRUCTIVE FILE OPS / RANSOMWARE — own temp/config vs user data?"
g 'remove_file|remove_dir_all|unlink|rmdir|shutil\.rmtree|os\.remove|rm -rf|shred|truncate|fs::write|encrypt|AES|chmod 000'

section "4. ROOTKIT / PERSISTENCE — any WRITE here is the finding"
g 'bashrc|zshrc|\.profile|crontab|authorized_keys|systemd|/etc/|autostart|LaunchAgents|LD_PRELOAD|ld\.so|/etc/hosts'

section "5. PROCESS EXECUTION — command from argv (fine) or network/env/file?"
g 'Command::new|process::Command|execve|execvp|\.spawn\(|system\(|subprocess|os\.system|child_process|sh -c|bash -c|[^a-z]eval\('

section "6. OBFUSCATION / HIDDEN PAYLOADS — decode-then-run?"
g 'base64|b64decode|fromCharCode|atob|include_bytes|include_str|dlopen|libloading|ctypes|transmute|exec\(compile'
echo "-- hex/byte escapes (\\xNN — benign if ANSI \\x1b, suspect if a blob):"
g '\\x[0-9a-f]{2}'

section "7. HARDCODED NETWORK INDICATORS — exclude loopback/test/DNS IPs"
g '([0-9]{1,3}\.){3}[0-9]{1,3}|\.onion|pastebin|discord.*webhook|t\.me/'

section "8. SUPPLY CHAIN — CI/release: curl|sh? unpinned actions? leaked secrets?"
g 'curl.*\|.*sh|wget.*\|.*sh|uses:.*@(main|master)|sha256sums|integrity"'

section "9. PRIVILEGE ESCALATION (informational, unscored — read in context)"
g 'sudo |pkexec|setuid|seteuid|capset|setcap |chmod (0?777|\+s)|chown root'

section "HEURISTIC TRIAGE (not a real verdict — see note below)"
# Narrow, low-false-positive patterns that are almost never innocent.
# grep can't tell benign from malicious in general; these specific combos can.
flag() { # <label> <pattern>  -> prints + counts if matched
  local hits; hits=$(g "$2" | grep -vcE '(/test|_test|test_|/tests/)')  # grep -c prints 0 on no match
  if [ "$hits" -gt 0 ]; then
    printf '  \033[1;31m⚠ %-28s\033[0m %s non-test hit(s)\n' "$1" "$hits"
    g "$2" | grep -vE '(/test|_test|test_|/tests/)' | head -3 | sed 's/^/      /'
    HIGH=$((HIGH + hits))
  fi
}
HIGH=0
flag "pipe-to-shell"        'curl[^|]*\|[^|]*sh|wget[^|]*\|[^|]*sh'
flag "decode-then-exec"     'exec\([^)]*(decode|atob|b64)|eval\([^)]*(decode|atob|fromCharCode)'
flag "authorized_keys write" '>>?[^<]*authorized_keys|authorized_keys.*<<'
flag "crontab/rc write"     '>>?[^<]*(crontab|\.bashrc|\.zshrc|\.profile)|crontab -'
flag "LD_PRELOAD set"       'LD_PRELOAD[[:space:]]*='
flag "rm -rf home/root"     'rm -rf[[:space:]]+["'\''$]*(/|~|\$HOME|/\*)'
flag "tor/paste/webhook C2" '\.onion|pastebin\.com|discord.*webhook|t\.me/|hastebin'
flag "unpinned CI action"   'uses:[^@]*@(main|master)[[:space:]]*$'
# NOTE: privilege-escalation patterns (chmod 777, pkexec, setuid) are NOT scored
# — they false-positive on policy strings, docs, and other scanners' patterns.
# They're surfaced unscored in §9 above for you to read in context.

# Committed binaries — you cannot audit a blob by reading source (the classic
# source-audit bypass). `file` ships on every unix. ELF/PE/Mach-O in a source
# tree warrants manual review regardless.
BINS=$(find "$TARGET" -type f -not -path '*/.git/*' -not -path '*/target/*' \
  -not -path '*/node_modules/*' -exec file {} + 2>/dev/null \
  | grep -iE 'ELF |PE32|Mach-O' | grep -viE ':.*(ASCII|text)')
if [ -n "$BINS" ]; then
  n=$(printf '%s\n' "$BINS" | grep -c .)
  printf '  \033[1;31m⚠ %-28s\033[0m %s executable blob(s) — cannot audit by reading source\n' "committed binary" "$n"
  printf '%s\n' "$BINS" | head -3 | sed 's/^/      /'
  HIGH=$((HIGH + n))
fi

# setuid/setgid files — almost never legitimate inside a source checkout.
SUID=$(find "$TARGET" -not -path '*/.git/*' -perm /6000 -type f 2>/dev/null)
if [ -n "$SUID" ]; then
  n=$(printf '%s\n' "$SUID" | grep -c .)
  printf '  \033[1;31m⚠ %-28s\033[0m %s file(s)\n' "setuid/setgid" "$n"
  printf '%s\n' "$SUID" | head -3 | sed 's/^/      /'
  HIGH=$((HIGH + n))
fi

# Opportunistic real scanners — only if already installed; skipped silently
# otherwise (no install burden). Nonzero exit == findings. cd is scoped to a
# subshell per run so HIGH still increments in this (parent) shell.
scan() { command -v "$1" >/dev/null 2>&1; }
run_in() { ( cd "$TARGET" && "$@" ) >/dev/null 2>&1; }
tool_flag() { printf '  \033[1;31m⚠ %-28s\033[0m findings (run the tool to see them)\n' "$1"; HIGH=$((HIGH + 1)); }
scan gitleaks  && ! run_in gitleaks detect --no-git -r /dev/null              && tool_flag "gitleaks: secrets"
scan cargo     && [ -f "$TARGET/Cargo.lock" ]        && ! run_in cargo audit -q             && tool_flag "cargo audit: vuln deps"
scan npm       && [ -f "$TARGET/package-lock.json" ] && ! run_in npm audit --audit-level=high && tool_flag "npm audit: vuln deps"
scan pip-audit && ! run_in pip-audit -q              && tool_flag "pip-audit: vuln deps"
scan semgrep   && ! run_in semgrep --config=p/security --error -q            && tool_flag "semgrep: security rules"
scan trivy     && ! run_in trivy fs --quiet --exit-code 1 --severity HIGH,CRITICAL . && tool_flag "trivy: vulns"
scan clamscan  && ! run_in clamscan -ri --no-summary .                       && tool_flag "clamav: known malware"
# yara needs rules; only meaningful if the caller supplies them.
[ -n "${YARA_RULES:-}" ] && scan yara && ! run_in yara -r "$YARA_RULES" .    && tool_flag "yara: rule match"

printf '\n\033[1m── VERDICT ──\033[0m\n'
if [ "$HIGH" -gt 0 ]; then
  printf '\033[1;31mSUSPICIOUS\033[0m — %d high-signal pattern hit(s). Manual review REQUIRED.\n' "$HIGH"
  EXIT=1
else
  printf '\033[1;32mNO HIGH-SIGNAL PATTERNS MATCHED\033[0m — but this is NOT a clean bill.\n'
  printf 'Grep cannot judge intent. Still read §1–8 hits above (dynamic endpoints,\n'
  printf 'secret reads paired with network calls, unusual file writes) before trusting it.\n'
  EXIT=0
fi
exit "${EXIT:-0}"
