#!/usr/bin/env python3
"""TEST_TLS_001 .. TEST_TLS_010 for the ProofGate host reference proxy.

Clients: the pinned OpenSSL 3.6.1 `s_client` (group control), Python `ssl`
(also OpenSSL 3.6.1), and real Chrome. Success is judged on the *negotiated*
group reported independently by the client and by the server log, never on
"TLS 1.3" alone.
"""
import glob, os, random, re, shutil, socket, ssl, subprocess, tempfile, time, unittest

from common import *

GET_HEALTH = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def setUpModule():
    ensure_stack()


class TlsTests(unittest.TestCase):
    # ------------------------------------------------------------------ 001
    def test_001_tls13_x25519mlkem768_succeeds(self):
        rc, out = s_client(["-tls1_3", "-groups", REQUIRED_GROUP], GET_HEALTH)
        self.assertIn("HTTP/1.1 200 OK", out, out)
        self.assertIn('{"status":"ok"}', out)
        self.assertIn("Protocol: TLSv1.3", out)
        self.assertIn("Cipher is TLS_AES_256_GCM_SHA384", out)

    # ------------------------------------------------------------------ 002
    def test_002_tls12_rejected(self):
        off = log_size()
        rc, out = s_client(["-tls1_2"], GET_HEALTH)
        self.assertNotIn("HTTP/1.1 200", out)
        self.assertRegex(out, r"(?i)alert|handshake failure|protocol version|wrong version|no protocols")
        # also TLS 1.2 with a classic ECDHE suite explicitly
        rc, out = s_client(["-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"], GET_HEALTH)
        self.assertNotIn("HTTP/1.1 200", out)
        # TLS 1.1 / 1.0 are not even buildable in this OpenSSL config; raw SSLv3-style hello:
        time.sleep(0.2)
        self.assertNotIn("TLS id=", "\n".join(l for l in log_since(off).splitlines() if "version=TLSv1.2" in l))
        self.assertTrue(proxy_alive())

    # ------------------------------------------------------------------ 003
    def test_003_x25519_alone_rejected(self):
        rc, out = s_client(["-tls1_3", "-groups", "X25519"], GET_HEALTH)
        self.assertNotIn("HTTP/1.1 200", out, out)
        self.assertRegex(out, r"(?i)alert|handshake failure|no shared")

    # ------------------------------------------------------------------ 004
    def test_004_secp256r1_alone_rejected(self):
        rc, out = s_client(["-tls1_3", "-groups", "secp256r1"], GET_HEALTH)
        self.assertNotIn("HTTP/1.1 200", out, out)
        self.assertRegex(out, r"(?i)alert|handshake failure|no shared")

    # ------------------------------------------------------------------ 005
    def _client_hello(self):
        ctx = tls_context()
        inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        o = ctx.wrap_bio(inb, outb, server_hostname="localhost")
        try:
            o.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return outb.read()

    def test_005_malformed_client_hello_does_not_crash(self):
        ch = self._client_hello()
        self.assertGreater(len(ch), 1000, "PQ ClientHello should be large (ML-KEM share)")
        rnd = random.Random(1234)
        cases = [b"", b"\x16", b"\x16\x03\x01", b"\x16\x03\x01\x00\x05hello", b"\x00" * 100, b"GET / HTTP/1.1\r\n\r\n",
                 b"\xff" * 5000, bytes(rnd.getrandbits(8) for _ in range(20000)),
                 b"\x16\x03\x01\xff\xff" + b"A" * 70000,                       # oversized record length
                 b"\x16\x03\x03\x00\x04\x01\x00\x00\x00",                      # empty ClientHello
                 b"\x16\x03\x03\x00\x04\x01\xff\xff\xff"]                      # claimed 16MB handshake
        for n in range(0, len(ch), 37):                                         # every truncation
            cases.append(ch[:n])
        for _ in range(400):                                                    # mutations
            b = bytearray(ch)
            for _ in range(rnd.randint(1, 8)):
                b[rnd.randrange(len(b))] = rnd.getrandbits(8)
            cases.append(bytes(b))
        for _ in range(50):                                                     # length-field corruption
            b = bytearray(ch)
            i = rnd.choice([3, 4, 6, 7, 8, 9])
            b[i] = rnd.getrandbits(8)
            cases.append(bytes(b))
        pid = int(open(os.path.join(ROOT, "build/run/proxy.pid")).read())
        for c in cases:
            try:
                s = socket.create_connection((HOST, PORT), timeout=2)
                s.sendall(c)
                s.settimeout(0.05)
                try:
                    s.recv(4096)
                except (socket.timeout, OSError):
                    pass
                s.close()
            except OSError:
                pass
        os.kill(pid, 0)  # raises if the proxy died
        self.assertTrue(proxy_alive())
        self.assertIn("pg-proxy: listening", log_since(0))
        self.assertNotIn("panicked", log_since(0))

    # ------------------------------------------------------------------ 006
    def test_006_negotiated_group_is_reported_and_verified(self):
        off = log_size()
        rc, out = s_client(["-tls1_3", "-groups", REQUIRED_GROUP], GET_HEALTH)
        m = re.search(r"Negotiated TLS1\.3 group: (\S+)", out)
        self.assertIsNotNone(m, out)
        self.assertEqual(m.group(1), REQUIRED_GROUP)           # client's view
        time.sleep(0.3)
        lines = [l for l in log_since(off).splitlines() if l.startswith("TLS id=")]
        self.assertTrue(lines)
        self.assertIn(f"group={REQUIRED_GROUP}", lines[-1])    # server's own view
        self.assertIn("version=TLSv1.3", lines[-1])
        self.assertIn("cipher=TLS_AES_256_GCM_SHA384", lines[-1])
        # client advertising several groups (incl. classical) still lands on the hybrid
        rc, out = s_client(["-tls1_3", "-groups", "X25519MLKEM768:X25519:secp256r1"], GET_HEALTH)
        self.assertRegex(out, r"Negotiated TLS1\.3 group: X25519MLKEM768", out)

    # ------------------------------------------------------------------ 007
    def test_007_no_fallback_for_non_pqc_clients(self):
        off = log_size()
        for groups in ["X25519:secp256r1:secp384r1:x448", "ffdhe2048", "MLKEM768", "SecP256r1MLKEM768",
                       "SecP384r1MLKEM1024", "secp384r1:secp521r1"]:
            rc, out = s_client(["-tls1_3", "-groups", groups], GET_HEALTH)
            self.assertNotIn("HTTP/1.1 200", out, f"groups={groups}\n{out}")
            # a failed handshake reports no group (<NULL>), never a real one
            self.assertNotRegex(out, r"Negotiated TLS1\.3 group: (?!<NULL>)\S+", out)
            self.assertRegex(out, r"alert|handshake failure", out)
        # Python client restricted to a classical curve
        ctx = tls_context()
        ctx.set_ecdh_curve("prime256v1")
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            s = socket.create_connection((HOST, PORT), timeout=5)
            ctx.wrap_socket(s, server_hostname="localhost")
        time.sleep(0.3)
        self.assertEqual([l for l in log_since(off).splitlines() if l.startswith("TLS id=")], [])
        self.assertTrue(proxy_alive())

    # ------------------------------------------------------------------ 008
    @unittest.skipUnless(shutil.which("google-chrome"), "Chrome not installed")
    def test_008_chrome_connects_with_pqc(self):
        off = log_size()
        prof = tempfile.mkdtemp(prefix="pg-chrome-")
        try:
            p = subprocess.run(
                ["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", f"--user-data-dir={prof}",
                 "--ignore-certificate-errors", "--no-first-run", "--disable-extensions",
                 "--virtual-time-budget=5000", "--dump-dom", f"https://localhost:{PORT}/health"],
                capture_output=True, timeout=60)
        finally:
            shutil.rmtree(prof, ignore_errors=True)
        dom = p.stdout.decode("utf-8", "replace")
        self.assertIn('"status":"ok"', dom, dom + p.stderr.decode("utf-8", "replace")[-500:])
        time.sleep(0.3)
        lines = [l for l in log_since(off).splitlines() if l.startswith("TLS id=")]
        self.assertTrue(lines, "server saw no completed handshake from Chrome")
        for l in lines:
            self.assertIn(f"group={REQUIRED_GROUP}", l)
        ver = subprocess.run(["google-chrome", "--version"], capture_output=True).stdout.decode().strip()
        print(f"\n    [TEST_TLS_008] {ver}: {len(lines)} handshake(s), group={REQUIRED_GROUP}")

    # ------------------------------------------------------------------ 009
    def test_009_zero_rtt_not_accepted(self):
        d = tempfile.mkdtemp()
        sess = os.path.join(d, "sess.pem")
        try:
            rc, out = s_client(["-tls1_3", "-groups", REQUIRED_GROUP, "-sess_out", sess], GET_HEALTH)
            self.assertIn("HTTP/1.1 200", out)
            self.assertTrue(os.path.exists(sess) and os.path.getsize(sess) > 0, "no session ticket issued\n" + out)
            # Ticket must advertise max_early_data = 0 (server-side 0-RTT disabled).
            show = subprocess.run([OPENSSL, "sess_id", "-in", sess, "-text", "-noout"], capture_output=True,
                                  env=dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf"))
                                  ).stdout.decode()
            self.assertRegex(show, r"Max Early Data: 0")
            self.assertNotRegex(show, r"Max Early Data: [1-9]")
            # Try to resume and push early data anyway.
            early = os.path.join(d, "early.txt")
            open(early, "wb").write(b"GET /early-marker-0rtt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            off = log_size()
            rc, out2 = s_client(["-tls1_3", "-groups", REQUIRED_GROUP, "-sess_in", sess, "-early_data", early], GET_HEALTH)
            self.assertNotRegex(out2, r"Early data was accepted")
            time.sleep(0.3)
            lg = log_since(off)
            if "Max Early Data" in out2 or "Max Early Data" in out:
                self.assertNotRegex(out + out2, r"Max Early Data: [1-9]")
            # The marker request must never have been processed as early data:
            # if it appears at all it must come after the handshake completed.
            tls_lines = [i for i, l in enumerate(lg.splitlines()) if l.startswith("TLS id=")]
            marker = [i for i, l in enumerate(lg.splitlines()) if "early-marker-0rtt" in l]
            for m in marker:
                self.assertTrue(tls_lines and tls_lines[0] < m, "early request processed before handshake completion")
            # Resumption (if it happened) still used a PQC group.
            for l in lg.splitlines():
                if l.startswith("TLS id="):
                    self.assertIn(f"group={REQUIRED_GROUP}", l)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ------------------------------------------------------------------ 010
    def test_010_no_secrets_in_logs_or_responses(self):
        key_pem = open(os.path.join(ROOT, "config/dev/key.pem")).read()
        key_body = [l for l in key_pem.splitlines() if l and not l.startswith("-----")]
        off = log_size()
        d = tempfile.mkdtemp()
        keylog = os.path.join(d, "keys.log")
        try:
            outs = []
            for req in (GET_HEALTH, b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                        b"BREW / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                        b"GET /api/models HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"):
                rc, out = s_client(["-tls1_3", "-groups", REQUIRED_GROUP, "-keylogfile", keylog], req)
                outs.append(out)
            rc, out = s_client(["-tls1_3", "-groups", "X25519"], GET_HEALTH)  # failed handshake path
            outs.append(out)
            time.sleep(0.3)
            lg = log_since(off)
            secrets = []
            for l in open(keylog).read().splitlines():
                parts = l.split()
                if len(parts) == 3:
                    secrets += [parts[1], parts[2]]   # client random and traffic secret (hex)
            self.assertGreater(len(secrets), 4)
            haystack = lg + "\n".join(outs).split("---")[0]
            # responses only (strip s_client's own print-out of its own handshake)
            bodies = "".join(o.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in o else "" for o in outs)
            for blob, name in ((lg, "proxy log"), (bodies, "HTTP responses")):
                self.assertNotIn("PRIVATE KEY", blob, name)
                for line in key_body:
                    self.assertNotIn(line, blob, f"private key material in {name}")
                for sec in secrets:
                    if len(sec) >= 32:
                        self.assertNotIn(sec.lower(), blob.lower(), f"TLS secret in {name}")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_010b_sslkeylogfile_env_is_ignored(self):
        # The running proxy was started without SSLKEYLOGFILE; make sure the binary
        # contains no keylog callback by starting a second instance with it set.
        d = tempfile.mkdtemp()
        kl = os.path.join(d, "kl.log")
        conf = os.path.join(d, "p.conf")
        txt = open(os.path.join(ROOT, "config/test/proxy.conf")).read().replace("127.0.0.1:8443", "127.0.0.1:18443")
        txt = txt.replace("config/dev/", os.path.join(ROOT, "config/dev/"))
        open(conf, "w").write(txt)
        p = subprocess.Popen([os.path.join(ROOT, "target/release/pg-proxy"), "--config", conf],
                             env=dict(os.environ, SSLKEYLOGFILE=kl), stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.6)
            cmd = [OPENSSL, "s_client", "-connect", "127.0.0.1:18443", "-tls1_3", "-groups", REQUIRED_GROUP]
            subprocess.run(cmd, input=GET_HEALTH, capture_output=True, timeout=10,
                           env=dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf")))
            self.assertFalse(os.path.exists(kl) and os.path.getsize(kl) > 0, "proxy wrote a TLS key log")
        finally:
            p.terminate()
            p.wait()
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
