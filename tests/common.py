"""Shared fixtures for the qedos host tests (no third-party packages)."""
import atexit, json, os, re, socket, ssl, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OPENSSL_CANDIDATES = [
    os.path.join(ROOT, "third_party/openssl-install/bin/openssl"),
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
]
OPENSSL = next((p for p in _OPENSSL_CANDIDATES if os.path.isfile(p)), "openssl")
PROXY_LOG = os.path.join(ROOT, "build/run/proxy.log")
HOST, PORT = "127.0.0.1", 8443
REQUIRED_GROUP = "X25519MLKEM768"
_started = False


SIGN_KEY = os.path.join(ROOT, "config/keys/config-signing-key.pem")
_orig_popen = subprocess.Popen


def sign_config(conf_path, key_path=SIGN_KEY):
    env = dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf"))
    p = subprocess.run(
        [OPENSSL, "pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", conf_path],
        capture_output=True,
        check=True,
        env=env,
    )
    sig_hex = p.stdout.hex() + "\n"
    with open(conf_path + ".sig", "w", encoding="ascii") as fh:
        fh.write(sig_hex)
    return conf_path + ".sig"


def _popen_hook(args, *a, **kw):
    env = kw.get("env")
    if isinstance(args, (list, tuple)) and "--config" in args and env and "SSLKEYLOGFILE" in env:
        idx = list(args).index("--config")
        if idx + 1 < len(args):
            cpath = args[idx + 1]
            if os.path.exists(cpath) and not os.path.exists(cpath + ".sig"):
                sign_config(cpath)
    return _orig_popen(args, *a, **kw)


subprocess.Popen = _popen_hook


def port_open(port=PORT):
    try:
        socket.create_connection((HOST, port), timeout=0.5).close()
        return True
    except OSError:
        return False


def ensure_stack(conf="config/test/proxy.conf"):
    global _started
    if port_open() and port_open(19001):
        return
    cpath = os.path.join(ROOT, conf)
    if os.path.exists(cpath) and not os.path.exists(cpath + ".sig"):
        sign_config(cpath)
    subprocess.run([os.path.join(ROOT, "scripts/dev-up.sh"), cpath], check=True,
                   stdout=subprocess.DEVNULL)
    _started = True
    atexit.register(lambda: subprocess.run([os.path.join(ROOT, "scripts/dev-down.sh")]))
    for _ in range(50):
        if port_open() and port_open(19001):
            return
        time.sleep(0.1)
    raise RuntimeError("stack did not come up")


def log_size():
    try:
        return os.path.getsize(PROXY_LOG)
    except OSError:
        return 0


def log_since(off):
    with open(PROXY_LOG, "rb") as f:
        f.seek(off)
        return f.read().decode("utf-8", "replace")


def s_client(args, data=b"", timeout=15, env=None):
    """Run the pinned OpenSSL 3.6.1 s_client against the proxy."""
    cmd = [OPENSSL, "s_client", "-connect", f"{HOST}:{PORT}", "-CAfile", os.path.join(ROOT, "config/dev/cert.pem"), "-ign_eof"] + args
    e = dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf"))
    if env:
        e.update(env)
    p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=e)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def connect(timeout=5):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    return tls_context().wrap_socket(s, server_hostname="localhost")


def recv_all(sock, limit=1 << 26, idle=3.0):
    """Read until EOF or until `idle` seconds without data."""
    sock.settimeout(idle)
    buf = b""
    try:
        while len(buf) < limit:
            d = sock.recv(65536)
            if not d:
                break
            buf += d
    except (socket.timeout, ssl.SSLError, ConnectionError, OSError):
        pass
    return buf


def raw(data, idle=2.0, timeout=5):
    """Open a TLS connection, send raw bytes, return everything received."""
    s = connect(timeout)
    try:
        s.sendall(data)
        return recv_all(s, idle=idle)
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def status_of(resp):
    m = re.match(rb"HTTP/1\.1 (\d{3})", resp)
    return int(m.group(1)) if m else None


def split_response(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    return head.decode("latin1"), body


def backend_log(port=19001):
    import http.client
    c = http.client.HTTPConnection(HOST, port, timeout=5)
    c.request("GET", "/__log__")
    r = json.loads(c.getresponse().read())
    c.close()
    return r


def backend_reset():
    import http.client
    for port in (19001, 19002):
        c = http.client.HTTPConnection(HOST, port, timeout=5)
        c.request("GET", "/__reset__")
        c.getresponse().read()
        c.close()


def proxy_alive():
    s = raw(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    return status_of(s) == 200
