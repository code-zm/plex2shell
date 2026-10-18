#!/usr/bin/env bash
# Regression tests for the plex2shell detections.
# Builds synthetic fixtures only: benign system libraries with a YUV-dump-shaped
# 0x80 tail appended, plus text fixtures. No payload is compiled or loaded.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
RULES="$HERE/../yara/plex2shell.yar"
HUNT="$HERE/../hunt/plex2shell-hunt.sh"
FIX="$HERE/fixtures"
FAIL=0
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=1; }

# expect FILE "Rule1 Rule2" | expect FILE ""  (exact set of matching rules)
expect() {
    local got
    got=$(yara -w "$RULES" "$1" 2>&1 | awk '{print $1}' | sort | tr '\n' ' ' | sed 's/ $//')
    local want
    want=$(printf '%s\n' $2 | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$want" ]; then pass "$(basename "$1"): [${want:-no match}]"
    else fail "$(basename "$1"): want [${want:-no match}] got [${got:-no match}]"; fi
}

# pad FILE to N frames of 640x360 yuv420p with 0x80, mimicking the dump-yuv output shape
yuv_pad() {
    local src=$1 dst=$2 frames=${3:-3} total
    total=$((345600 * frames))
    cp -- "$src" "$dst"
    head -c $((total - $(stat -L -c %s "$src"))) /dev/zero | tr '\0' '\200' >> "$dst"
}

ELF_SRC=$(ls /usr/lib/libz.so.1* 2>/dev/null | head -1)
PE_SRC=$(ls /usr/x86_64-w64-mingw32/bin/*.dll 2>/dev/null | head -1)

echo "== YARA: binary structure rules"
if [ -n "$ELF_SRC" ]; then
    cp -- "$ELF_SRC" "$T/clean.so"
    yuv_pad "$ELF_SRC" "$T/zz12345.so"
    cp -- "$ELF_SRC" "$T/zeropad.so"; head -c 200000 /dev/zero >> "$T/zeropad.so"
    expect "$T/clean.so" ""
    expect "$T/zz12345.so" "Plex2Shell_Dropped_Codec_ELF_YUV_Overlay Plex2Shell_Dropped_Codec_PoC_Geometry"
    # generic rule must not depend on padding value or geometry
    expect "$T/zeropad.so" "Plex2Shell_Dropped_Codec_ELF_YUV_Overlay"
else
    echo "SKIP  no /usr/lib/libz.so.1 for ELF fixtures"
fi
if [ -n "$PE_SRC" ]; then
    cp -- "$PE_SRC" "$T/clean.dll"
    yuv_pad "$PE_SRC" "$T/hevc_decoder.dll"
    expect "$T/clean.dll" ""
    expect "$T/hevc_decoder.dll" "Plex2Shell_Dropped_Codec_PE_YUV_Overlay Plex2Shell_Dropped_Codec_PoC_Geometry"
else
    echo "SKIP  no mingw DLL for PE fixtures"
fi

echo "== YARA: text artifacts"
expect "$FIX/pms_malicious.log"         "Plex2Shell_PMS_Log_Or_Prefs_Artifacts"
expect "$FIX/pms_benign.log"            ""
expect "$FIX/Preferences_malicious.xml" "Plex2Shell_PMS_Log_Or_Prefs_Artifacts"
expect "$FIX/Preferences_benign.xml"    ""
expect "$HERE/../../plex2shell.py"      "Plex2Shell_Exploit_Tool"
expect "$HERE/../../payload_linux.c"    "Plex2Shell_Payload_Source_Templates"
expect "$HERE/../../payload_windows.c"  "Plex2Shell_Payload_Source_Templates"

echo "== hunt script"
mk_tree() {   # mk_tree DIR prefs log [codec-file]
    local d="$1/Library/Application Support/Plex Media Server"
    mkdir -p "$d/Logs" "$d/Codecs/abc1234-0123456789abcdef0123456789-linux-x86_64"
    cp -- "$2" "$d/Preferences.xml"
    cp -- "$3" "$d/Logs/Plex Media Server.log"
    [ -n "${4:-}" ] && cp -- "$4" "$d/Codecs/abc1234-0123456789abcdef0123456789-linux-x86_64/"
    [ -n "$ELF_SRC" ] && cp -- "$ELF_SRC" "$d/Codecs/abc1234-0123456789abcdef0123456789-linux-x86_64/libbenign.so"
    printf '%s' "$d"
}
BAD=$(mk_tree "$T/bad" "$FIX/Preferences_malicious.xml" "$FIX/pms_malicious.log" "$T/zz12345.so")
GOOD=$(mk_tree "$T/good" "$FIX/Preferences_benign.xml" "$FIX/pms_benign.log")

"$HUNT" -P -a "$BAD" > "$T/bad.out" 2>&1; rc=$?
nhit=$(grep -c '^\[HIT\]' "$T/bad.out")
if [ $rc -eq 2 ] && [ "$nhit" -ge 5 ]; then pass "compromised tree: exit 2, $nhit hits"
else fail "compromised tree: exit $rc, $nhit hits"; cat "$T/bad.out"; fi

"$HUNT" -P -a "$GOOD" > "$T/good.out" 2>&1; rc=$?
if [ $rc -eq 0 ]; then pass "clean tree: exit 0"
else fail "clean tree: exit $rc"; cat "$T/good.out"; fi

[ "${VERBOSE:-0}" = 1 ] && { echo; cat "$T/bad.out"; }
exit $FAIL
