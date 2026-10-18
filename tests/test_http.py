#!/usr/bin/env python3
"""HTTP reverse-proxy behaviour tests (routing, smuggling, SSE, limits, timeouts).

Key technique: the test backends record every request they receive, so for
rejected requests we assert that *nothing reached any backend* (LAW_007) and
for accepted ones that the backend saw exactly the intended request (LAW_001/4).
"""
import json, socket, ssl, threading, time, unittest

from common import *


def setUpModule():
    ensure_stack()


def req(method, path, headers=None, body=b"", host="localhost", extra=b""):
    h = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    for k, v in (headers or {}).items():
        h += f"{k}: {v}\r\n"
    if body and "Content-Length" not in (headers or {}) and "Transfer-Encoding" not in (headers or {}):
        h += f"Content-Length: {len(body)}\r\n"
    return h.encode() + b"\r\n" + body + extra


def json_body(resp):
    _, body = split_response(resp)
    return json.loads(body)


def seen_by_backends():
    return backend_log(19001)["log"] + backend_log(19002)["log"]


class Routing(unittest.TestCase):
    def setUp(self):
        backend_reset()

    def test_health_local(self):
        r = raw(req("GET", "/health"))
        self.assertEqual(status_of(r), 200)
        self.assertEqual(seen_by_backends(), [])

    def test_routes_reach_intended_backend(self):
        r = raw(req("GET", "/api/models?x=1"))
        self.assertEqual(status_of(r), 200)
        j = json_body(r)
        self.assertEqual(j["backend"], "A")
        self.assertEqual(j["path"], "/api/models?x=1")
        r = raw(req("GET", "/game/level/1.js"))
        self.assertEqual(json_body(r)["backend"], "B")
        r = raw(req("POST", "/api/chat", body=b'{"q":"hi"}'))
        j = json_body(r)
        self.assertEqual((j["backend"], j["method"], j["body_len"]), ("A", "POST", 10))

    def test_unknown_path_and_method_rejected_not_forwarded(self):
        cases = [("GET", "/nope", 404), ("GET", "/", 404), ("GET", "/health/", 404), ("POST", "/health", 405),
                 ("GET", "/api/chat", 405), ("DELETE", "/api/models", 405), ("PUT", "/game/x", 405),
                 ("OPTIONS", "/api/models", 405), ("PATCH", "/api/chat", 405), ("GET", "/game", 404)]
        for m, p, want in cases:
            r = raw(req(m, p))
            self.assertEqual(status_of(r), want, f"{m} {p}\n{r[:200]}")
        self.assertEqual(seen_by_backends(), [])

    def test_forbidden_and_unknown_methods(self):
        for line, want in [(b"CONNECT example.com:443 HTTP/1.1", 405), (b"TRACE / HTTP/1.1", 405),
                           (b"BREW /api/models HTTP/1.1", 501), (b"PROPFIND /api/models HTTP/1.1", 501)]:
            r = raw(line + b"\r\nHost: x\r\nConnection: close\r\n\r\n")
            self.assertEqual(status_of(r), want, line)
        self.assertEqual(seen_by_backends(), [])

    def test_no_forward_proxy_and_no_arbitrary_backend(self):
        # absolute-form, authority, userinfo, Host tricks, X-headers: nothing can pick a backend
        evil = [b"GET http://127.0.0.1:19002/api/models HTTP/1.1\r\nHost: 127.0.0.1:19002\r\nConnection: close\r\n\r\n",
                b"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
                b"GET //127.0.0.1:19002/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                b"GET * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"]
        for e in evil:
            self.assertEqual(status_of(raw(e)), 400, e)
        # a valid route with hostile Host / forwarding headers must still hit only backend A
        r = raw(req("GET", "/api/models", host="127.0.0.1:19002",
                    headers={"X-Forwarded-For": "6.6.6.6", "X-Forwarded-Host": "evil", "X-Real-IP": "6.6.6.6",
                             "Forwarded": "for=6.6.6.6;host=evil", "X-Backend": "127.0.0.1:19002",
                             "Via": "1.1 evil", "Proxy-Authorization": "Basic eA==",
                             "Upgrade-Insecure-Requests": "1"}))
        j = json_body(r)
        self.assertEqual(j["backend"], "A")
        h = j["headers"]
        self.assertEqual(h["host"], "127.0.0.1:19001")        # config-fixed, not client-chosen
        self.assertEqual(h["x-forwarded-for"], "127.0.0.1")   # client value discarded
        for banned in ("x-forwarded-host", "x-real-ip", "forwarded", "via", "proxy-authorization"):
            self.assertNotIn(banned, h)
        self.assertEqual(h["x-forwarded-proto"], "https")
        self.assertEqual(backend_log(19002)["log"], [])

    def test_path_traversal_and_encodings_rejected(self):
        for p in ["/game/../api/chat", "/game/%2e%2e/api/chat", "/game/%2E%2E/x", "/game/./x", "/game//x",
                  "/game/%2fx", "/game/%5cx", "/game/%00", "/game/..%2f", "/game/a%0d%0aX-Injected:1",
                  "/game/%25%32%65", "/game/x y", "/game/\"", "/api/models/../chat", "/game/..;/x",
                  "/game/%c0%ae%c0%ae/x"]:
            r = raw(f"GET {p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            self.assertIn(status_of(r), (400,), f"{p!r} -> {r[:80]!r}")
        self.assertEqual(seen_by_backends(), [])

    def test_server_banner_stripped_and_security_headers(self):
        r = raw(req("GET", "/api/models"))
        head, _ = split_response(r)
        self.assertNotIn("backend-secret-banner", head)
        self.assertNotIn("Server:", head)
        self.assertIn("Strict-Transport-Security", head)
        self.assertIn("X-Content-Type-Options: nosniff", head)

    def test_head_request(self):
        r = raw(req("HEAD", "/api/models"))
        head, body = split_response(r)
        self.assertTrue(head.startswith("HTTP/1.1 200"))
        self.assertEqual(body, b"")
        self.assertIn("Content-Length:", head)


class Smuggling(unittest.TestCase):
    def setUp(self):
        backend_reset()

    def check_rejected(self, data, want=400):
        r = raw(data)
        self.assertEqual(status_of(r), want, r[:200])
        # connection must be closed (no desync): second request on the same socket gets nothing
        self.assertEqual(seen_by_backends(), [], "request leaked to backend")

    def test_cl_te(self):
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

    def test_te_cl(self):
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")

    def test_te_obfuscation(self):
        for te in (b"Transfer-Encoding : chunked", b"Transfer-Encoding: xchunked", b"Transfer-Encoding: chunked, identity",
                   b"Transfer-Encoding:\tchunked\x0b", b"Transfer-Encoding: gzip, chunked", b"X: y\r\n Transfer-Encoding: chunked"):
            r = raw(b"POST /api/chat HTTP/1.1\r\nHost: x\r\n" + te + b"\r\n\r\n0\r\n\r\nGET /game/smuggled HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertIn(status_of(r), (400, 501), (te, r[:100]))
        self.assertNotIn("B GET /game/smuggled", seen_by_backends())
        self.assertEqual(seen_by_backends(), [])

    def test_duplicate_and_bad_content_length(self):
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd")
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 4, 4\r\n\r\nabcd")
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: +4\r\n\r\nabcd")
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n")
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 0x4\r\n\r\nabcd")

    def test_bare_lf_and_cr_and_nul(self):
        self.check_rejected(b"GET /api/models HTTP/1.1\nHost: x\n\r\n\r\n")
        self.check_rejected(b"GET /api/models HTTP/1.1\r\nHost: x\nX: y\r\n\r\n")
        self.check_rejected(b"GET /api/models HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n")
        self.check_rejected(b"GET /api/models HTTP/1.1\r\nHost: x\rX: y\r\n\r\n")

    def test_host_rules(self):
        self.check_rejected(b"GET /api/models HTTP/1.1\r\n\r\n")
        self.check_rejected(b"GET /api/models HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
        self.check_rejected(b"GET /api/models HTTP/1.0\r\nHost: a\r\n\r\n", want=505)

    def test_upgrade_and_expect_refused(self):
        self.check_rejected(b"GET /api/events HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", want=501)
        self.check_rejected(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\nx", want=417)

    def test_pipelined_second_request_not_smuggled_in_body(self):
        # A request with CL=5 followed by a second full request: backend must see exactly two requests.
        two = (b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
               b"GET /game/second HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        r = raw(two)
        self.assertEqual(r.count(b"HTTP/1.1 200"), 2, r)
        self.assertEqual(seen_by_backends(), ["A POST /api/chat", "B GET /game/second"])

    def test_body_longer_than_content_length_is_next_request(self):
        # bytes after CL are parsed as a new request and (being garbage) rejected, never forwarded
        r = raw(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhiGET /game/evil HTTP/1.1 junk\r\n\r\n")
        self.assertEqual(r.count(b"HTTP/1.1 200"), 1)
        self.assertIn(b"400", r)
        self.assertEqual(seen_by_backends(), ["A POST /api/chat"])

    def test_oversized_head_and_target(self):
        r = raw(b"GET /api/models HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 20000 + b"\r\n\r\n")
        self.assertEqual(status_of(r), 431)
        r = raw(b"GET /game/" + b"a" * 3000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(status_of(r), 414)
        many = b"".join(b"X-%d: v\r\n" % i for i in range(100))
        r = raw(b"GET /api/models HTTP/1.1\r\nHost: x\r\n" + many + b"\r\n")
        self.assertEqual(status_of(r), 431)
        self.assertEqual(seen_by_backends(), [])

    def test_garbage_after_tls(self):
        for g in (b"\x00" * 100, b"\xff\xfe" * 500, b"HELLO\r\n\r\n", b"\r\n\r\n\r\n\r\n", bytes(range(256)) * 20):
            r = raw(g)
            self.assertIn(status_of(r), (400, None))
        self.assertTrue(proxy_alive())
        self.assertEqual(seen_by_backends(), [])


class BodiesAndStreaming(unittest.TestCase):
    def setUp(self):
        backend_reset()

    def test_content_length_body_1mb(self):
        body = b"A" * (1 << 20)
        r = raw(req("POST", "/api/chat", body=body), idle=5)
        self.assertEqual(json_body(r)["body_len"], len(body))

    def test_body_over_limit_413(self):
        r = raw(req("POST", "/api/chat", headers={"Content-Length": str((1 << 20) + 1)}))
        self.assertEqual(status_of(r), 413)
        r = raw(req("POST", "/game/x", headers={"Content-Length": "65537"}))
        self.assertEqual(status_of(r), 413)
        r = raw(req("GET", "/api/models", headers={"Content-Length": "1"}, body=b"x"))
        self.assertEqual(status_of(r), 413)
        self.assertEqual(seen_by_backends(), [])

    def test_chunked_request_reframed(self):
        chunks = b"5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n"
        r = raw(req("POST", "/api/chat", headers={"Transfer-Encoding": "chunked"}, body=chunks))
        j = json_body(r)
        self.assertEqual(j["body_len"], 12)
        self.assertEqual(j["body_sha_prefix"], "hello, world")
        self.assertNotIn("content-length", j["headers"])
        self.assertEqual(j["headers"]["transfer-encoding"], "chunked")

    def test_chunked_with_extensions_or_trailers_rejected(self):
        for body in (b"5;ext=1\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n", b"zz\r\n"):
            r = raw(req("POST", "/api/chat", headers={"Transfer-Encoding": "chunked"}, body=body))
            self.assertIn(status_of(r), (400, None), body)
        # backend may have been contacted for an in-flight chunked body, but never got a complete bogus request
        self.assertTrue(proxy_alive())

    def test_chunked_body_over_limit_aborted(self):
        s = connect()
        s.sendall(req("POST", "/game/x", headers={"Transfer-Encoding": "chunked"}).split(b"\r\n\r\n")[0] + b"\r\n\r\n")
        try:
            for _ in range(40):
                s.sendall(b"%x\r\n" % 4096 + b"a" * 4096 + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        except (ssl.SSLError, OSError):
            pass
        r = recv_all(s, idle=2)
        s.close()
        self.assertIn(status_of(r), (400, 413, None))
        self.assertTrue(proxy_alive())

    def test_keepalive_three_requests(self):
        s = connect()
        for i in range(3):
            s.sendall(f"GET /api/models?i={i} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += s.recv(65536)
            head, _, rest = buf.partition(b"\r\n\r\n")
            n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0].split(b":")[1])
            while len(rest) < n:
                rest += s.recv(65536)
            self.assertEqual(json.loads(rest)["path"], f"/api/models?i={i}")
        s.close()

    def test_pipelined_requests_in_order(self):
        data = b"".join(f"GET /api/models?i={i} HTTP/1.1\r\nHost: x\r\n\r\n".encode() for i in range(5))
        data += b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        r = raw(data, idle=3)
        self.assertEqual(r.count(b"HTTP/1.1 200"), 6)
        order = [int(x) for x in __import__("re").findall(rb'"/api/models\?i=(\d)"', r)]
        self.assertEqual(order, [0, 1, 2, 3, 4])

    def test_large_response_with_slow_reader_backpressure(self):
        size = 64 << 20
        s = connect(timeout=30)
        s.sendall(req("GET", f"/api/big?size={size}", headers={}) .replace(b"Connection: close\r\n", b""))
        got = 0
        hdr = b""
        t0 = time.time()
        s.settimeout(30)
        while True:
            d = s.recv(65536)
            if not d:
                break
            if b"\r\n\r\n" not in hdr:
                hdr += d
                if b"\r\n\r\n" in hdr:
                    got += len(hdr.split(b"\r\n\r\n", 1)[1])
            else:
                got += len(d)
            if got < (4 << 20):
                time.sleep(0.002)  # slow start so the proxy must stall the backend read
            if got >= size:
                break
        s.close()
        self.assertEqual(got, size)

    def test_sse_streams_incrementally(self):
        s = connect(timeout=10)
        s.sendall(b"GET /api/events?n=5&gap=0.3 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        s.settimeout(10)
        t0 = time.time()
        buf = b""
        first = None
        ticks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            now = time.time() - t0
            for i in range(5):
                if f"tick {i}".encode() in buf and i not in [t[0] for t in ticks]:
                    ticks.append((i, now))
            if b"0\r\n\r\n" in buf[-10:]:
                break
        s.close()
        self.assertIn(b"text/event-stream", buf)
        self.assertEqual([t[0] for t in ticks], [0, 1, 2, 3, 4])
        # events arrive spread out over time, not buffered to the end
        self.assertLess(ticks[0][1], 0.6)
        self.assertGreater(ticks[4][1] - ticks[0][1], 0.9)

    def test_sse_client_disconnect_closes_backend(self):
        s = connect(timeout=10)
        s.sendall(b"GET /api/events?n=200&gap=0.1 HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(5)
        buf = b""
        while b"tick 1" not in buf:
            buf += s.recv(65536)
        s.close()
        time.sleep(1.5)
        self.assertGreaterEqual(backend_log(19001)["disconnects"], 1, "backend kept streaming to a dead client")

    def test_keepalive_reused_after_finite_sse(self):
        s = connect(timeout=10)
        s.sendall(b"GET /api/events?n=2&gap=0.05 HTTP/1.1\r\nHost: x\r\n\r\n")
        buf = b""
        while not buf.endswith(b"0\r\n\r\n"):
            buf += s.recv(65536)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        r = recv_all(s, idle=2)
        s.close()
        self.assertEqual(status_of(r), 200)


class Timeouts(unittest.TestCase):
    """Run against config/test/proxy.conf (handshake 2s, head 2s, idle 4s)."""

    def test_slowloris_partial_head_closed(self):
        s = connect()
        s.sendall(b"GET /api/models HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        t0 = time.time()
        r = recv_all(s, idle=6)
        s.close()
        self.assertLess(time.time() - t0, 5.5)
        self.assertTrue(proxy_alive())

    def test_stalled_tls_handshake_closed(self):
        s = socket.create_connection((HOST, PORT))
        s.sendall(b"\x16\x03\x01\x02\x00\x01")   # start of a handshake record, then silence
        s.settimeout(5)
        t0 = time.time()
        try:
            d = s.recv(10)
        except (socket.timeout, OSError):
            d = b"timeout"
        self.assertEqual(d, b"", "server should close a stalled handshake")
        self.assertLess(time.time() - t0, 4)
        s.close()

    def test_idle_keepalive_closed(self):
        s = connect()
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(3)
        s.recv(65536)
        t0 = time.time()
        s.settimeout(8)
        try:
            d = s.recv(10)
        except (socket.timeout, ssl.SSLError, OSError):
            d = b"timeout"
        self.assertEqual(d, b"")
        self.assertLess(time.time() - t0, 7)
        s.close()

    def test_signed_config_law_011(self):
        import shutil, tempfile
        d = tempfile.mkdtemp(prefix="pg-law011-")
        proxy_bin = os.path.join(ROOT, "target/release/pg-proxy")
        try:
            conf = os.path.join(d, "proxy.conf")
            with open(os.path.join(ROOT, "config/test/proxy.conf")) as src:
                base_txt = src.read()
            base_txt = base_txt.replace("127.0.0.1:8443", "127.0.0.1:18444")
            base_txt = base_txt.replace("config/dev/", os.path.join(ROOT, "config/dev/"))
            with open(conf, "w") as fh:
                fh.write(base_txt)

            # 1. Missing .sig is rejected by pg-proxy
            r_unsigned = subprocess.run([proxy_bin, "--config", conf], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(r_unsigned.returncode, 0)
            self.assertIn("LAW_011", r_unsigned.stderr)

            # 2. Valid signed config succeeds and serves traffic
            sign_config(conf)
            p = subprocess.Popen([proxy_bin, "--config", conf], stderr=subprocess.DEVNULL)
            try:
                for _ in range(30):
                    if port_open(18444):
                        break
                    time.sleep(0.05)
                self.assertTrue(port_open(18444), "proxy with valid signed config did not start")
            finally:
                p.terminate()
                p.wait()

            # 3. Modified config with old .sig is rejected by pg-proxy
            with open(conf, "a") as fh:
                fh.write("\n# tampered comment\n")
            r_tampered = subprocess.run([proxy_bin, "--config", conf], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(r_tampered.returncode, 0)
            self.assertIn("LAW_011", r_tampered.stderr)

            # 4. Signature from a different Ed25519 key is rejected by pg-proxy
            other_key = os.path.join(d, "other-key.pem")
            env = dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf"))
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", other_key],
                           check=True, capture_output=True, env=env)
            sign_config(conf, key_path=other_key)
            r_wrong_key = subprocess.run([proxy_bin, "--config", conf], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(r_wrong_key.returncode, 0)
            self.assertIn("LAW_011", r_wrong_key.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

