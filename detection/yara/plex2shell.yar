/*
    plex2shell detection rules
    CVE-2026-96652 / -96654 / -96655 / -96656 (Plex Media Server < 1.43.3.10861)

    Rule tiers (see meta.confidence):
      high    - artifact-structure rules; survive payload/tool changes
      medium  - payload/tool strings from the public PoC; break if recompiled with changes
      hunting - weak on their own; use to prioritise triage, not to alert

    Suggested scan targets:
      Linux:   /var/lib/plexmediaserver/Library/Application Support/Plex Media Server
      Docker:  <config volume>/Library/Application Support/Plex Media Server
      Windows: %LOCALAPPDATA%\Plex Media Server
    e.g.  yara -r -w plex2shell.yar "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server"

    Requires YARA >= 4.2 (math.count / math.entropy with offsets, pe.overlay).

    Validation (2026-10-18, YARA 4.5.7):
      - dropped-codec rules: dump files written by the real "Plex Transcoder" from PMS
        1.43.2.10687 (offline re-run of a logged PoC job) and by stock libx264 dump-yuv
      - payload rules: PoC templates built with the PoC's own flags on gcc 11-16, clang 17/18/21,
        mingw-w64 13/16, at -O0..-O3, -Os, stripped and unstripped
      - log rule: real PMS 1.43.2.10687 logs from a lab that was attacked with the PoC
      - false positives: none across /usr/lib, /usr/bin, /opt, /usr/share, the PMS 1.43.2 install tree
        and its downloaded Codecs, except where noted in a rule's meta
*/

import "elf"
import "pe"
import "math"
import "hash"

/* ------------------------------------------------------------------ dropped codec (on-disk) */

rule Plex2Shell_Dropped_Codec_ELF_YUV_Overlay
{
    meta:
        description = "ELF shared object followed by a large uniform tail - the shape of a library written via the x264 dump-yuv option (CVE-2026-96655) for loading from the Plex Codecs dir (CVE-2026-96656)"
        confidence  = "high"
        reference   = "https://zmain.info/blog/plex2shell"
        notes       = "The dump writes whole raw YUV frames, so the planted library is the payload ELF followed by the rest of the luma plane and the chroma planes. That tail is not mapped by any segment and is near-zero entropy. The padding byte value does not matter to this rule. Outside the Plex dirs it also matches Metasploit mettle.bin/sniffer.bin (ELF + zero-filled config area)."

    condition:
        uint32(0) == 0x464C457F
        and elf.type == elf.ET_DYN
        and filesize > 128KB
        // section header table (when present) ends well before EOF
        and (elf.sh_offset == 0
             or elf.sh_offset + elf.number_of_sections * elf.sh_entry_size + 65536 <= filesize)
        // no loadable data reaches the tail
        and for all i in (0 .. elf.number_of_segments - 1) :
            ( elf.segments[i].offset + elf.segments[i].file_size + 65536 <= filesize )
        and math.entropy(filesize - 65536, 65536) < 0.5
}

rule Plex2Shell_Dropped_Codec_PE_YUV_Overlay
{
    meta:
        description = "PE DLL with a large, near-uniform overlay - the shape of a DLL written via the x264 dump-yuv option into the Plex Codecs dir (Windows variant, PoC drops hevc_decoder.dll)"
        confidence  = "high"
        reference   = "https://zmain.info/blog/plex2shell"
        notes       = "Entropy is measured on the last 64 KiB, which always lies inside the overlay: unstripped mingw builds (the PoC does not pass -s) carry a COFF symbol/string table at the start of the overlay, which lifts whole-overlay entropy above 2."

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.overlay.size > 65536
        and math.entropy(filesize - 65536, 65536) < 0.5
}

rule Plex2Shell_Dropped_Codec_PoC_Geometry
{
    meta:
        description = "ELF or PE whose size is a whole number of 640x360 yuv420p frames (345600 B) and whose tail is 0x80 padding - matches the default plex2shell.py carrier geometry"
        confidence  = "high"
        notes       = "Tool-default specific. Changing the geometry or padding byte defeats it; the *_YUV_Overlay rules do not depend on either."

    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D)
        and filesize % 345600 == 0
        and math.count(0x80, filesize - 65536, 65536) > 65000
}

rule Plex2Shell_Dropped_Codec_Repeated_Frame
{
    meta:
        description = "ELF or PE whose leading 4 KiB recurs at an offset that divides the file size - the dump of a carrier whose frames all hold the same payload (plex2shell.py encodes 3 identical frames)"
        confidence  = "high"
        notes       = "Independent of geometry, padding value and tail entropy, so it still fires if the padding is randomised to beat the *_YUV_Overlay rules. Misses a single-frame carrier."

    strings:
        $elf = { 7F 45 4C 46 }
        $mz  = { 4D 5A }

    condition:
        filesize > 128KB and filesize < 64MB
        and (
            (uint32(0) == 0x464C457F and for any i in (2 .. #elf) : (
                @elf[i] >= 65536 and filesize % @elf[i] == 0
                and hash.md5(@elf[i], 4096) == hash.md5(0, 4096) ))
            or
            (uint16(0) == 0x5A4D and for any i in (2 .. #mz) : (
                @mz[i] >= 65536 and filesize % @mz[i] == 0
                and hash.md5(@mz[i], 4096) == hash.md5(0, 4096) ))
        )
}

/* ------------------------------------------------------------------ payloads (compiled from the PoC templates) */

rule Plex2Shell_Linux_Payload_NoLibc_Constructor
{
    meta:
        description = "Libc-free ELF shared object that issues fork, execve and exit back-to-back from one function and carries /bin/sh -c - matches payload_linux.c"
        confidence  = "medium"
        notes       = "Applies to both the compiled pay.so and the dumped codec file (the payload sits at offset 0 of the dump). The ordering/proximity requirement is what separates the payload from static libcs and static-PIE binaries (musl libc.so/ld-musl, including the copy shipped in /usr/lib/plexmediaserver/lib, static ripgrep), which also have raw syscall stubs, /bin/sh and no DT_NEEDED. Observed spans in payload builds: fork->execve <= 0x66, execve->exit <= 0x19."

    strings:
        $sh    = "/bin/sh" ascii
        $dc    = "-c" ascii
        // -O1 and up: the inline syscall wrapper is folded into the constructor
        $fork  = { ( B8 39 00 00 00 | 48 C7 C0 39 00 00 00 ) [0-24] 0F 05 }
        $exec  = { ( B8 3B 00 00 00 | 48 C7 C0 3B 00 00 00 ) [0-24] 0F 05 }
        $exit  = { ( B8 3C 00 00 00 | 48 C7 C0 3C 00 00 00 ) [0-24] 0F 05 }
        // -O0: the syscall number is passed in edi to the out-of-line wrapper
        $fork0 = { BF 39 00 00 00 [0-16] E8 }
        $exec0 = { BF 3B 00 00 00 [0-16] E8 }
        $exit0 = { BF 3C 00 00 00 [0-16] E8 }

    condition:
        uint32(0) == 0x464C457F
        and elf.type == elf.ET_DYN
        and for none i in (0 .. elf.dynamic_section_entries - 1) :
            ( elf.dynamic[i].type == elf.DT_NEEDED )
        and $sh and $dc
        and (
            for any i in (1 .. #fork) : ( for any j in (1 .. #exec) : (
                @exec[j] > @fork[i] and @exec[j] - @fork[i] < 256
                and for any k in (1 .. #exit) : ( @exit[k] > @exec[j] and @exit[k] - @exec[j] < 64 ) ))
            or
            for any i in (1 .. #fork0) : ( for any j in (1 .. #exec0) : (
                @exec0[j] > @fork0[i] and @exec0[j] - @fork0[i] < 256
                and for any k in (1 .. #exit0) : ( @exit0[k] > @exec0[j] and @exit0[k] - @exec0[j] < 64 ) ))
        )
}

rule Plex2Shell_Linux_Payload_RevShell_Command
{
    meta:
        description = "ELF containing the plex2shell.py default reverse-shell command line (bash /dev/tcp + script PTY upgrade)"
        confidence  = "medium"

    strings:
        $a = "exec 0<>/dev/tcp/" ascii
        $b = "exec /usr/bin/script -qc /bin/bash /dev/null" ascii
        $c = "/usr/bin/setsid /usr/bin/bash -c" ascii

    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule Plex2Shell_Windows_Payload_DLL
{
    meta:
        description = "Reverse-shell DLL from payload_windows.c: DllMain re-spawns itself under rundll32 ,RunShell and speaks a READY / __CMDEND__ line protocol"
        confidence  = "medium"

    strings:
        $p1 = "READY\r\n" ascii
        $p2 = "__CMDEND__\r\n" ascii
        $p3 = "ERR:CreateProcess\r\n" ascii
        $s1 = "rundll32.exe \"%s\",RunShell" ascii
        $s2 = "cmd.exe /c \"%s\"" ascii
        $s3 = "Rundll32" ascii

    condition:
        uint16(0) == 0x5A4D
        and (
            (pe.exports("RunShell") and 2 of them)
            or 4 of them
        )
}

/* ------------------------------------------------------------------ PMS logs and Preferences.xml */

rule Plex2Shell_PMS_Log_Or_Prefs_Artifacts
{
    meta:
        description = "Plex Media Server log lines or Preferences.xml values left by the plex2shell chain"
        confidence  = "high"
        scan_target = "Logs/Plex Media Server*.log, Preferences.xml"
        notes       = "Line formats checked against PMS 1.43.2.10687 logs. GET request lines (timeline/subscribe, searchOne, resources, transcode, and the transcoder 'Job running:' command line) are DEBUG and need debug logging, the PMS default; 'PUT /:/prefs' lines are INFO and are logged either way. Patterns tolerate single/double URL-encoding."

    strings:
        // CVE-2026-96652: protocol= carries a URL instead of a bare scheme
        $ssrf   = /\/player\/timeline\/subscribe\?([^\r\n]{0,512}&)?protocol=[a-z0-9+.\-]{1,16}(%3a|%253a|:)(%2f|%252f|\/){2}/ nocase
        // CVE-2026-96654: searchOne identifier= injected with /function/ path traversal
        $agent  = /searchOne\?([^\r\n]{0,512}&)?identifier=[^&\r\n]{0,256}(%2f|%252f|\/)function(%2f|%252f|\/)/ nocase
        // CVE-2026-96655: dump-yuv file-writing option in TranscoderH264Options
        $h264   = /TranscoderH264Options(="|=|%3d)[^"&\r\n]{0,512}dump(-|%2d)yuv/ nocase
        // CVE-2026-96655: stats= file-writing option in TranscoderH264Options
        $h264s  = /TranscoderH264Options(="|=|%3d)[^"&\r\n]{0,512}stats(=|%3d)/ nocase
        // agent SSRF function name (appears in injected identifiers, not in normal agent calls)
        $gfn    = "GetResultFromNetwork" nocase
        // set-id discovery: resources endpoint asked for an absolute path or traversal
        $res    = /resources\/[^?\s]{0,64}\?([^\r\n]{0,512}&)?resource_name=(%2f|%5c|\/|\\|[a-z](%3a|:)|[^&\r\n]{0,256}(\.\.|%2e%2e))/ nocase
        // transcoder pointed at a non-loopback http(s) item (crude loopback exclusion; YARA has no lookahead)
        $xcode  = /transcode\/universal\/[a-z]{1,16}(\.m3u8|\.mpd)?\?([^\r\n]{0,1024}&)?path=https?(%3a|:)(%2f|\/){2}([^1l\[&%]|1[^2]|12[^7]|l[^o])/ nocase

    condition:
        filesize < 512MB
        and ($ssrf or $agent or $h264 or $h264s or ($gfn and $res) or ($res and $xcode))
}

/* ------------------------------------------------------------------ attacker tooling */

rule Plex2Shell_Exploit_Tool
{
    meta:
        description = "Source or script implementing the plex2shell chain (any language) - for tooling found on compromised hosts, shares or repos"
        confidence  = "medium"

    strings:
        $e1 = "/player/timeline/subscribe" ascii wide
        $e2 = "/player/proxy/poll" ascii wide
        $e3 = "searchOne" ascii wide
        $e4 = "GetResultFromNetwork" ascii wide
        $e5 = "TranscoderH264Options" ascii wide
        $e6 = "dump-yuv" ascii wide
        $e7 = "/transcode/universal/" ascii wide
        $e8 = "resource_name" ascii wide
        $e9 = "sslip.io" ascii wide
        $pmslog = "DEBUG - Request: [" ascii   // PMS log lines carry the same strings; leave those to the log rule

    condition:
        filesize < 5MB and 5 of ($e*) and not $pmslog
}

rule Plex2Shell_Payload_Source_Templates
{
    meta:
        description = "payload_linux.c / payload_windows.c templates shipped with plex2shell"
        confidence  = "medium"

    strings:
        $l1 = "\"__CMD__\"" ascii
        $l2 = "__attribute__((constructor))" ascii
        $l3 = "\"syscall\"" ascii
        $w1 = "\"__IP__\"" ascii
        $w2 = "htons(__PORT__)" ascii
        $w3 = "__CMDEND__" ascii
        $w4 = "RunShell" ascii

    condition:
        filesize < 1MB and (all of ($l*) or 3 of ($w*))
}

/* ------------------------------------------------------------------ carrier (hunting) */

rule Plex2Shell_Hunt_Lossless_AllIntra_x264_MP4
{
    meta:
        description = "MP4 encoded with lossless (qp=0), all-intra (keyint=1) x264 - how plex2shell carries a binary bit-exactly through the Plex transcoder"
        confidence  = "hunting"
        notes       = "Payload bytes are CABAC-coded and not visible in the file; this keys only on encoder settings. Lossless all-intra H.264 is rare in distributed media but legitimate in production/intermediate workflows. Do not alert on this alone."

    strings:
        $x264 = "x264 - core" ascii
        $cqp  = "rc=cqp" ascii
        $qp0  = " qp=0" ascii
        $ki1  = "keyint=1 " ascii

    condition:
        uint32be(4) == 0x66747970   // 'ftyp'
        and all of them
}
