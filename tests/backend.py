#!/usr/bin/env python3
"""Test backends A (port 19001) and B (19002) for the ProofGate host tests.

Every response echoes what the backend actually received so tests can assert
what the proxy forwarded (headers, body length, raw request line).
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAMES = {19001: "A", 19002: "B"}
REQLOG = []


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _body(self):
        te = self.headers.get("Transfer-Encoding", "")
        if te.lower() == "chunked":
            data = b""
            while True:
                line = self.rfile.readline().strip()
                n = int(line, 16)
                if n == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(n)
                self.rfile.readline()
            return data
        n = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(n) if n else b""

    def _reply(self, status, obj):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Server", "backend-secret-banner")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _handle(self):
        name = NAMES[self.server.server_port]
        if self.path == "/__log__":
            self._reply(200, {"log": [l for l in REQLOG if l.startswith(name + " ")], "disconnects": self.server.disconnects})
            return
        if self.path == "/__reset__":
            REQLOG.clear()
            self.server.disconnects = 0
            self._reply(200, {"ok": True})
            return
        body = self._body()
        REQLOG.append(f"{name} {self.command} {self.path}")
        if self.path.startswith("/api/events"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            n = 5
            if "n=" in self.path:
                n = int(self.path.split("n=")[1].split("&")[0])
            gap = 0.2
            if "gap=" in self.path:
                gap = float(self.path.split("gap=")[1].split("&")[0])
            try:
                for i in range(n):
                    ev = f"data: tick {i}\n\n".encode()
                    self.wfile.write(f"{len(ev):x}\r\n".encode() + ev + b"\r\n")
                    self.wfile.flush()
                    time.sleep(gap)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                self.server.disconnects += 1
            return
        if self.path.startswith("/api/big"):
            size = int(self.path.split("size=")[1]) if "size=" in self.path else 1 << 20
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            chunk = b"x" * 65536
            left = size
            try:
                while left:
                    n = min(left, len(chunk))
                    self.wfile.write(chunk[:n])
                    left -= n
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self._reply(200, {
            "backend": name,
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body_len": len(body),
            "body_sha_prefix": body[:16].decode("latin1"),
        })

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _handle


class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 4096
    disconnects = 0


if __name__ == "__main__":
    servers = []
    for port in (19001, 19002):
        s = S(("127.0.0.1", port), H)
        servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("backends up", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
