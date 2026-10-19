# plex2shell

Unauth RCE chain for Plex Media Server < 1.43.3.10828. Fixed in 1.43.3.10861. Update ASAP.

**CVSS 3.1: 9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

Write-up: **<https://zmain.info/blog/plex2shell>**


## Disclaimer

This tool is published for authorized security testing, academic research,
and defensive purposes only. Use it only against systems you own or have
explicit written permission to test. The authors are not responsible for
misuse or damage caused by this tool. Unauthorized access to computer
systems is illegal.

## CVEs

| CVE | Primitive |
| --- | --- |
| CVE-2026-96652 | Unauthenticated SSRF via `/player/timeline` `protocol=` |
| CVE-2026-96654 | Loopback pivot: dead auth guard + `searchOne` `identifier=` injection |
| CVE-2026-96655 | Owner-authed transcoder SSRF + arbitrary-path file write (`dump-yuv`) |
| CVE-2026-96656 | Code execution via unsigned codec `dlopen` in the Codecs set-dir |

## Prerequisites

- Python 3.8+, `ffmpeg`, `gcc` (or `x86_64-w64-mingw32-gcc` for Windows targets)
- Attacker host reachable from the target (media fetch + reverse shell)

## License

GPLv3
