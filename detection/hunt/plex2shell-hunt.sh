#!/usr/bin/env bash
# plex2shell-hunt.sh - read-only triage for the plex2shell chain on Linux / Docker hosts
#   CVE-2026-96652 / -96654 / -96655 / -96656 (Plex Media Server < 1.43.3.10861)
#
# Usage: plex2shell-hunt.sh [-a APPSUPPORT_DIR]... [-y RULES.yar] [-P]
#   -a DIR   Plex "Application Support/Plex Media Server" dir (repeatable). Default: auto-discover.
#   -y FILE  YARA rules to run over each dir (default: ../yara/plex2shell.yar if yara is installed)
#   -P       skip live process checks (e.g. when examining a copied/offline config dir)
#
# Exit: 0 nothing found, 1 warnings only (review), 2 indicator hits.
# Run as root for complete /proc coverage. Nothing is modified.

set -u
LC_ALL=C

FIXED_BUILD="1.43.3.10861"
HITS=0
WARNS=0
DIRS=()
RULES=""
CHECK_PROCS=1
SELF_DIR=$(cd "$(dirname "$0")" && pwd)

hit()  { HITS=$((HITS + 1));  printf '[HIT]  %s\n' "$*"; }
warn() { WARNS=$((WARNS + 1)); printf '[WARN] %s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK]   %s\n' "$*"; }
indent() { cut -c1-400 | sed 's/^/         /'; }

while getopts "a:y:Ph" opt; do
    case "$opt" in
        a) DIRS+=("$OPTARG") ;;
        y) RULES="$OPTARG" ;;
        P) CHECK_PROCS=0 ;;
        *) sed -n '2,12p' "$0"; exit 0 ;;
    esac
done

if [ -z "$RULES" ] && [ -f "$SELF_DIR/../yara/plex2shell.yar" ]; then
    RULES="$SELF_DIR/../yara/plex2shell.yar"
fi

# ---------------------------------------------------------------- discovery
discover_dirs() {
    local d id src
    for d in "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server" \
             "/config/Library/Application Support/Plex Media Server" \
             "/snap/plexmediaserver/common/Library/Application Support/Plex Media Server"; do
        [ -d "$d" ] && DIRS+=("$d")
    done
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        while read -r id; do
            [ -n "$id" ] || continue
            src=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/config"}}{{.Source}}{{end}}{{end}}' "$id" 2>/dev/null)
            d="$src/Library/Application Support/Plex Media Server"
            if [ -n "$src" ] && [ -d "$d" ]; then
                info "docker container $id ($(docker inspect -f '{{.Config.Image}}' "$id")) -> $src"
                DIRS+=("$d")
            fi
        done < <(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | awk 'tolower($2) ~ /plex/ {print $1}')
    fi
}

[ ${#DIRS[@]} -eq 0 ] && discover_dirs
if [ ${#DIRS[@]} -eq 0 ]; then
    warn "no Plex Application Support dir found; pass one with -a"
fi

# ---------------------------------------------------------------- version
version_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

check_version() {
    local v=""
    if command -v dpkg-query >/dev/null 2>&1; then
        v=$(dpkg-query -W -f '${Version}' plexmediaserver 2>/dev/null)
    fi
    if [ -z "$v" ] && command -v rpm >/dev/null 2>&1; then
        v=$(rpm -q --qf '%{VERSION}' plexmediaserver 2>/dev/null) || v=""
    fi
    if [ -z "$v" ] && [ -n "${1:-}" ]; then
        v=$(grep -ahoE 'Plex Media Server v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$1"/Logs/Plex\ Media\ Server*.log 2>/dev/null \
            | sed 's/.* v//' | sort -V | tail -1)
    fi
    v=$(printf '%s' "$v" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    if [ -z "$v" ]; then
        info "could not determine PMS version"
    elif version_lt "$v" "$FIXED_BUILD"; then
        warn "PMS $v is older than $FIXED_BUILD - vulnerable to the plex2shell chain; update"
    else
        ok "PMS $v >= $FIXED_BUILD"
    fi
}

# ---------------------------------------------------------------- Preferences.xml
check_prefs() {
    local p="$1/Preferences.xml" val
    [ -f "$p" ] || { info "no Preferences.xml in $1"; return; }
    if ! grep -q 'TranscoderH264Options=' "$p"; then
        ok "Preferences.xml: TranscoderH264Options not set"
        return
    fi
    val=$(grep -oE 'TranscoderH264Options="[^"]*"' "$p")
    if printf '%s' "$val" | grep -qiE 'dump-yuv|stats='; then
        hit "Preferences.xml: file-writing x264 option persisted: $val"
    elif [ "$val" = 'TranscoderH264Options=""' ]; then
        warn "Preferences.xml: TranscoderH264Options present but empty (the PoC clears it this way after use; also possible if an admin toggled it)"
    else
        warn "Preferences.xml: non-default TranscoderH264Options: $val"
    fi
}

# ---------------------------------------------------------------- logs
LOG_HIGH=(
    '/player/timeline/subscribe\?([^ ]*&)?protocol=[a-z0-9+.-]{1,16}(%3a|%253a|:)'
    'searchOne\?[^ ]*identifier=[^& ]*(%2f|%252f|/)function(%2f|%252f|/)'
    'TranscoderH264Options(=|%3d)[^& ]*(dump(-|%2d)yuv|stats(=|%3d))'
)
LOG_MED=(
    'resources/[^? ]*\?([^ ]*&)?resource_name=(%2f|%5c|/|\\|[a-z](%3a|:)|[^& ]*(\.\.|%2e%2e))'
    '(sslip|nip)\.io'
    'X-Plex-Client-Identifier=(vfyclient01|poc_[0-9])|/TKN_[0-9]|X-Plex-Token=TOTALLY_INVALID_JUNK'
)
XCODE_EXT='transcode/universal/[^ ]*[?&]path=https?(%3a|:)(%2f|/){2}'
XCODE_LOOP='path=https?(%3a|:)(%2f|/){2}(127\.0\.0\.1|localhost|\[::1\]|%5b%3a%3a1%5d)(%3a|:|%2f|/)'

check_logs() {
    local logs=() m pat
    while IFS= read -r -d '' m; do logs+=("$m"); done \
        < <(find "$1/Logs" -maxdepth 1 -type f -name 'Plex Media Server*.log' -print0 2>/dev/null)
    if [ ${#logs[@]} -eq 0 ]; then
        info "no PMS logs under $1/Logs"
        return
    fi
    info "scanning ${#logs[@]} PMS log file(s) (PMS keeps only a few rotations - preserve them now)"
    for pat in "${LOG_HIGH[@]}"; do
        m=$(grep -aiE -- "$pat" "${logs[@]}" 2>/dev/null)
        [ -n "$m" ] && { hit "log: exploit request pattern /$pat/ ($(printf '%s\n' "$m" | wc -l) line(s))"; printf '%s\n' "$m" | head -5 | indent; }
    done
    for pat in "${LOG_MED[@]}"; do
        m=$(grep -aiE -- "$pat" "${logs[@]}" 2>/dev/null)
        [ -n "$m" ] && { warn "log: suspicious pattern /$pat/ ($(printf '%s\n' "$m" | wc -l) line(s))"; printf '%s\n' "$m" | head -5 | indent; }
    done
    m=$(grep -aiE -- "$XCODE_EXT" "${logs[@]}" 2>/dev/null | grep -viE -- "$XCODE_LOOP")
    [ -n "$m" ] && { warn "log: transcode of a non-loopback http(s) item ($(printf '%s\n' "$m" | wc -l) line(s))"; printf '%s\n' "$m" | head -5 | indent; }
}

# ---------------------------------------------------------------- Codecs dir
magic() { head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n'; }
tail_uniform() {
    [ "$(tail -c 65536 -- "$1" | od -An -v -tx1 | tr -s ' ' '\n' | sed '/^$/d' | sort -u | head -2 | wc -l)" -eq 1 ]
}

check_codecs() {
    local cdir="$1/Codecs" f mg sz n=0
    [ -d "$cdir" ] || { info "no Codecs dir in $1"; return; }
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        mg=$(magic "$f")
        case "$mg" in
            7f454c46*|4d5a*) ;;
            *) continue ;;
        esac
        sz=$(stat -c %s -- "$f")
        if [ "$sz" -ge 131072 ] && tail_uniform "$f"; then
            hit "Codecs: binary with uniform 64 KiB tail (dump-yuv write shape): $f ($sz B, mtime $(stat -c %y -- "$f"))"
        fi
        case "$(basename -- "$f")" in
            zz[0-9]*.so) hit "Codecs: PoC-style planted name: $f" ;;
        esac
    done < <(find "$cdir" -type f -print0 2>/dev/null)
    info "checked $n file(s) under $cdir"
    if [ -n "$RULES" ] && command -v yara >/dev/null 2>&1; then
        local y
        y=$(yara -r -w "$RULES" "$1" 2>/dev/null)
        if [ -n "$y" ]; then
            hit "YARA matches under $1:"
            printf '%s\n' "$y" | indent
        else
            ok "YARA: no matches under $1"
        fi
    elif [ -z "$RULES" ]; then
        info "YARA rules not found; skipping YARA scan"
    else
        info "yara not installed; skipping YARA scan"
    fi
}

# ---------------------------------------------------------------- live processes
SHELLS='^(sh|bash|dash|zsh|ash|ksh|busybox|setsid|script|nc|ncat|socat|python[0-9.]*|perl)$'

proc_name() {   # pid -> basename of exe, falling back to comm
    local e
    e=$(readlink "/proc/$1/exe" 2>/dev/null) && { basename -- "${e% (deleted)}"; return; }
    cat "/proc/$1/comm" 2>/dev/null
}

check_procs() {
    local pd pid ppid name pname cmd maps st env
    [ "$(id -u)" -eq 0 ] || warn "not root: process checks only cover your own processes"
    for pd in /proc/[0-9]*; do
        pid=${pd#/proc/}
        maps=$(grep -F '/Codecs/' "$pd/maps" 2>/dev/null | grep -F '(deleted)' | awk '{$1=$2=$3=$4=$5=""; print}' | sort -u)
        [ -n "$maps" ] && { hit "pid $pid ($(proc_name "$pid")) maps a deleted file from a Plex Codecs dir"; printf '%s\n' "$maps" | indent; }

        cmd=$(tr '\0' ' ' < "$pd/cmdline" 2>/dev/null)
        [ -n "$cmd" ] || continue
        if printf '%s' "$cmd" | grep -qE '/dev/(tcp|udp)/'; then
            hit "pid $pid: /dev/tcp reverse-shell command line: $(printf '%s' "$cmd" | cut -c1-200)"
        fi

        name=$(proc_name "$pid")
        printf '%s' "$name" | grep -qE "$SHELLS" || continue
        st=$(cat "$pd/stat" 2>/dev/null) || continue
        st=${st##*) }
        ppid=$(printf '%s' "$st" | awk '{print $2}')
        pname=$(proc_name "$ppid")
        case "$pname" in
            "Plex Transcoder"|"Plex Media Server"|"Plex Media Serv"|"Plex Script Hos"*)
                hit "pid $pid: $name spawned by $pname (pid $ppid): $(printf '%s' "$cmd" | cut -c1-200)" ;;
        esac
        if [ "$(stat -c %U "$pd" 2>/dev/null)" = "plex" ]; then
            env=$(tr '\0' '\n' < "$pd/environ" 2>/dev/null)
            if [ -r "$pd/environ" ] && ! printf '%s\n' "$env" | grep -q '^PATH='; then
                hit "pid $pid: $name running as plex with no PATH in its environment (payload execs with an empty envp)"
            else
                warn "pid $pid: $name running as user plex: $(printf '%s' "$cmd" | cut -c1-200)"
            fi
            if command -v ss >/dev/null 2>&1; then
                ss -tnpH 2>/dev/null | grep -F "pid=$pid," | indent
            fi
        fi
        case "$name" in
            script) printf '%s' "$cmd" | grep -qE -- '-qc /bin/(ba)?sh /dev/null' \
                        && warn "pid $pid: script PTY-upgrade pattern: $cmd" ;;
        esac
    done
}

# ---------------------------------------------------------------- main
printf 'plex2shell-hunt  %s  host=%s\n\n' "$(date -u +%FT%TZ)" "$(hostname)"
check_version "${DIRS[0]:-}"
for d in "${DIRS[@]}"; do
    printf '\n== %s\n' "$d"
    check_prefs "$d"
    check_logs "$d"
    check_codecs "$d"
done
if [ "$CHECK_PROCS" -eq 1 ]; then
    printf '\n== live processes\n'
    check_procs
fi

printf '\nsummary: %d hit(s), %d warning(s)\n' "$HITS" "$WARNS"
[ "$HITS" -gt 0 ] && exit 2
[ "$WARNS" -gt 0 ] && exit 1
exit 0
