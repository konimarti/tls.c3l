#!/usr/bin/env python3
"""Starts and stops the test peers (openssl s_server) and publishes where they listen.

  python3 -I tests/peer/run.py start [--scenario NAME ...]   start peers, write tests/peer/out/state.txt, exit
  python3 -I tests/peer/run.py stop                          kill every recorded peer
  python3 -I tests/peer/run.py run [--scenario NAME ...] -- CMD ...   start, run CMD, stop (for CI)
  python3 -I tests/peer/run.py serve NAME PORT               (internal) run one python peer in the foreground
  python3 -I tests/peer/run.py serve-test                    our server (build/tlsc --listen) against openssl s_client and raw bytes
  python3 -I tests/peer/run.py client-test                   our client (build/tlsc) against slow, dropping and silent python servers

The C3 tests read tests/peer/out/state.txt (KEY=value lines). Standard library only.
"""
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PKI = os.path.join(ROOT, "tests", "pki", "out")
OUT = os.path.join(HERE, "out")
PIDFILE = os.path.join(OUT, "peers.pid")
STATE = os.path.join(OUT, "state.txt")

# name -> (certificate base name in the PKI, extra s_server arguments)
SCENARIOS = {
    "tls13": ("server", ["-tls1_3", "-www"]),
    "tls12": ("server", ["-tls1_2", "-www"]),
    "rsa13": ("server-rsa", ["-tls1_3", "-www"]),
    "rsa12": ("server-rsa", ["-tls1_2", "-www"]),
    "rev13": ("server", ["-tls1_3", "-rev"]),
    "ip": ("ip-only", ["-www"]),
    # prints the messages it receives, so a test can read what the client really sent
    "trace13": ("server", ["-tls1_3", "-www", "-trace"]),
}
# peers with a broken or unusual certificate or protocol. They print the messages they get (-msg), so the tests can see
# that a rejected handshake ended with an alert and not with silence. A name with ":" is certificate:key, with
# "legacy" the OpenSSL configuration that lets s_server speak TLS 1.1.
LEGACY = "legacy"
LOW = ["-cipher", "DEFAULT:@SECLEVEL=0"]
NEGATIVE = {
    "expired": ("expired", ["-www", "-msg"], None),
    "notyet": ("notyet", ["-www", "-msg"], None),
    "wronghost": ("wronghost", ["-www", "-msg"], None),
    "untrusted": ("untrusted", ["-www", "-msg"], None),
    "selfsigned": ("selfsigned", ["-www", "-msg"], None),
    "noeku": ("wrong-eku", ["-www", "-msg"], None),
    "badint": ("bad-leaf", ["-www", "-msg", "-cert_chain", "@PKI/bad-intermediate.pem"], None),
    "cnonly": ("cn-only", ["-www", "-msg"], None),
    "dnsonly": ("dns-only", ["-www", "-msg"], None),
    "wildcard": ("wildcard", ["-www", "-msg"], None),
    "weakkey": ("rsa1024", ["-www", "-msg"] + LOW, None),
    "sha1sig": ("sha1-signed", ["-www", "-msg"] + LOW, None),
    "tls11": ("server", ["-tls1_1", "-www", "-msg"] + LOW, LEGACY),
    # offers h2 and http/1.1 and prints what the client sent (-trace shows the offered ALPN names)
    "alpn": ("server", ["-www", "-trace", "-alpn", "h2,http/1.1"], None),
    # alt.test gets another certificate: it can only verify if the client sent the name
    "sni2": ("server", ["-www", "-cert2", "@PKI/alt.pem", "-key2", "@PKI/alt.key", "-servername", "alt.test"], None),
    "mtls-wrongca": ("server", ["-tls1_3", "-www", "-msg", "-Verify", "1", "-verify_return_error", "-CAfile", "@CA"], None),
    "mtls12": ("server", ["-tls1_2", "-www", "-msg", "-Verify", "1", "-verify_return_error", "-CAfile", "@CA"], None),
}
for _n, (_c, _e, _x) in NEGATIVE.items():
    SCENARIOS[_n] = (_c, _e)
# Resumption peers: tickets (default), and session ids only (-no_ticket)
NEGATIVE_EXTRA = {
    "resume13": ("server", ["-tls1_3", "-www"]),
    "resume12": ("server", ["-tls1_2", "-www"]),
    "resume12id": ("server", ["-tls1_2", "-www", "-no_ticket"]),
}
SCENARIOS.update(NEGATIVE_EXTRA)
# Peers without -www read commands from a pipe the harness keeps open: a line of text is sent to the client, "r" asks
# for a renegotiation (TLS 1.2), "K" for a key update with a reply request (TLS 1.3). The pipe is tests/peer/out/NAME.cmd.
INTERACTIVE = {
    "reneg": ("server", ["-tls1_2", "-msg"]),
    "keyupdate": ("server", ["-tls1_3", "-msg"]),
}
SCENARIOS.update(INTERACTIVE)
CONFS = {LEGACY: ("openssl-legacy.cnf", "MinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n")}
# peers written in Python: raw TCP or the ssl module, each behaves in one specific way
PYTHON_PEERS = ["silent", "garbage", "echo12", "dropper", "closer", "sni"]  # sni also echoes (TLS 1.3)
DEFAULT = (["tls13", "tls12", "rsa13", "rsa12", "rev13", "ip", "trace13"] + PYTHON_PEERS + list(NEGATIVE)
           + list(NEGATIVE_EXTRA) + list(INTERACTIVE))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port, proc, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def kill_recorded():
    if not os.path.exists(PIDFILE):
        return
    with open(PIDFILE) as f:
        pids = [int(x) for x in f.read().split() if x.strip().isdigit()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    end = time.time() + 3
    while time.time() < end and any(alive(p) for p in pids):
        time.sleep(0.05)
    for pid in pids:
        if alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    os.remove(PIDFILE)


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # a zombie that nobody waited for still answers signal 0
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(") ")[-1].split()[0] != "Z"
    except OSError:
        return True


def start(names):
    # make the certificates if they are missing
    subprocess.check_call(["bash", os.path.join(ROOT, "tests", "pki", "make-pki.sh")])
    kill_recorded()
    os.makedirs(OUT, exist_ok=True)
    env = dict(os.environ, OPENSSL_CONF=os.path.join(PKI, "openssl-test.cnf"))
    for fname, body in CONFS.values():
        with open(os.path.join(OUT, fname), "w") as f:
            f.write("openssl_conf = d\n[d]\nssl_conf = s\n[s]\nsystem_default = sd\n[sd]\n" + body)
    pids = []
    lines = ["CA=" + os.path.join(PKI, "ca.pem"), "DIR=" + PKI, "OUT=" + OUT]
    # fingerprints computed independently of the library under test, for the pinning tests
    import hashlib
    for cert in ("server", "selfsigned"):
        with open(os.path.join(PKI, cert + ".pem")) as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
        lines.append("SHA256_%s=%s" % (cert, hashlib.sha256(der).hexdigest()))
    try:
        for name in names:
            port = free_port()
            log = open(os.path.join(OUT, name + ".log"), "wb")
            if name in PYTHON_PEERS:
                cmd = [sys.executable, "-I", os.path.abspath(__file__), "serve", name, str(port)]
            else:
                cert, extra = SCENARIOS[name]
                conf = NEGATIVE.get(name, (None, None, None))[2]
                peer_env = dict(env, OPENSSL_CONF=os.path.join(OUT, CONFS[conf][0])) if conf else env
                extra = [os.path.join(PKI, "ca.pem") if a == "@CA" else a.replace("@PKI", PKI) for a in extra]
                cert_file, key_file = cert.split(":") if ":" in cert else (cert + ".pem", cert + ".key")
                # commands on stdin only work without -quiet; the pipe never ends, so -ign_eof is not needed
                quiet = [] if name in INTERACTIVE else ["-quiet"]
                cmd = (["stdbuf", "-oL", "-eL"] if shutil.which("stdbuf") else []) + ["openssl", "s_server"] + quiet + [
                       "-accept", "127.0.0.1:%d" % port, "-cert", os.path.join(PKI, cert_file),
                       "-key", os.path.join(PKI, key_file)] + extra
            stdin = subprocess.DEVNULL
            if name in INTERACTIVE:
                fifo = os.path.join(OUT, name + ".cmd")
                if os.path.exists(fifo):
                    os.remove(fifo)
                os.mkfifo(fifo)
                # read-write: the peer itself holds a writer, so the pipe never reports end of input
                stdin = os.open(fifo, os.O_RDWR)
                lines.append("CMD_%s=%s" % (name, fifo))
            proc = subprocess.Popen(cmd, env=peer_env if name not in PYTHON_PEERS else env, stdin=stdin, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            pids.append(proc.pid)
            with open(PIDFILE, "w") as f:
                f.write("\n".join(str(p) for p in pids) + "\n")
            if not wait_listening(port, proc):
                raise RuntimeError("peer %s did not start (see %s.log)" % (name, name))
            lines.append("PORT_%s=%d" % (name, port))
        selftest(names, dict(l.split("=", 1) for l in lines))
    except BaseException:
        kill_recorded()
        raise
    with open(STATE, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(STATE)


def selftest(names, state):
    """The test CA against an independent client: openssl s_client must accept the peer."""
    if "tls13" not in names:
        return
    port = state["PORT_tls13"]
    r = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:" + port, "-CAfile", state["CA"],
                        "-verify_return_error", "-servername", "test.example", "-verify_hostname", "test.example"],
                       input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    if r.returncode != 0:
        sys.stderr.write(r.stdout.decode(errors="replace"))
        raise RuntimeError("selftest: openssl s_client does not accept the test peer")
    print("selftest: openssl s_client accepts the test peer")


def stop():
    kill_recorded()
    if os.path.exists(STATE):
        os.remove(STATE)


def tls_context(version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(PKI, "server.pem"), os.path.join(PKI, "server.key"))
    ctx.minimum_version = version
    ctx.maximum_version = version
    return ctx


def serve(name, port):
    """One peer that misbehaves (or behaves) in a single, specific way. Runs until killed."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(16)
    held = []  # connections the peer keeps open and quiet
    sni_log = os.path.join(OUT, "sni.log")
    version = ssl.TLSVersion.TLSv1_2 if name == "echo12" else ssl.TLSVersion.TLSv1_3
    ctx = tls_context(version) if name in ("echo12", "dropper", "closer", "sni") else None
    if name == "sni":
        def record_name(sock, server_name, context):
            with open(sni_log, "a") as f:
                f.write("%s\n" % server_name)
        ctx.sni_callback = record_name

    def handle(raw):
        try:
            if name == "silent":
                held.append(raw)  # never answers, never closes
                return
            if name == "garbage":
                raw.recv(4096)
                raw.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                raw.close()
                return
            conn = ctx.wrap_socket(raw, server_side=True)
            if name in ("echo12", "sni"):
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
                conn.close()
            elif name == "dropper":
                conn.recv(65536)  # the client's first application data
                plain = socket.socket(fileno=conn.detach())  # no close_notify
                plain.shutdown(socket.SHUT_WR)
                plain.close()
            elif name == "closer":
                conn.recv(65536)
                conn.sendall(b"bye")
                conn.unwrap()  # close_notify
                conn.close()
        except Exception:
            try:
                raw.close()
            except OSError:
                pass

    while True:
        raw, _ = listener.accept()
        threading.Thread(target=handle, args=(raw,), daemon=True).start()


TLSC = os.path.join(ROOT, "build", "tlsc")
V7 = bytes.fromhex("16030100540100005003030001020304050607 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                   "000002c02b0100002500000 00b0009000006612e74657374000a00040002 0017000d000400020403000b00020100".replace(" ", ""))


class Server:
    """build/tlsc --listen on a free port; its stderr (--verbose) goes to a file."""

    def __init__(self, tag, *args):
        self.port = free_port()
        self.err = os.path.join(OUT, "tlsc-%s.err" % tag)
        self.errf = open(self.err, "wb")
        self.proc = subprocess.Popen([TLSC, "--listen", str(self.port), "--cert", os.path.join(PKI, "server.pem"),
                                      "--key", os.path.join(PKI, "server.key"), "--verbose"] + list(args),
                                     stdout=subprocess.DEVNULL, stderr=self.errf, stdin=subprocess.DEVNULL)
        if not wait_listening(self.port, self.proc):
            raise RuntimeError("tlsc did not start, see " + self.err)

    def log(self):
        time.sleep(0.3)
        with open(self.err, "rb") as f:
            return f.read().decode(errors="replace")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.errf.close()


def s_client(port, extra, payload=b"hello\n", quiet=True):
    """openssl s_client sending a line and waiting a moment for the echo. Returns (exit code, output)."""
    cmd = ["openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-servername", "localhost",
           "-CAfile", os.path.join(PKI, "ca.pem"), "-verify_return_error"] + (["-quiet"] if quiet else []) + ["-no_ign_eof"] + extra
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        p.stdin.write(payload)
        p.stdin.flush()
        time.sleep(1.0)
        p.stdin.close()
        out = p.stdout.read()
        p.wait(10)
    except Exception:
        p.kill()
        raise
    return p.returncode, out.decode(errors="replace")


def raw_send(port, data, wait=1.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(data)
    time.sleep(0.2)
    s.settimeout(wait)
    try:
        reply = s.recv(4096)
    except (socket.timeout, OSError):
        reply = b""
    s.close()
    return reply


def serve_test():
    if not os.path.exists(TLSC):
        sys.stderr.write("build/tlsc is missing: run `c3c build tlsc` first\n")
        return 2
    subprocess.check_call(["bash", os.path.join(ROOT, "tests", "pki", "make-pki.sh")])
    os.makedirs(OUT, exist_ok=True)
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print("%s %s%s" % ("ok  " if ok else "FAIL", name, "" if ok else ": " + detail))

    srv = Server("plain")
    try:
        rc, out = s_client(srv.port, [])
        check("echo_13", rc == 0 and "hello" in out, "rc=%s out=%r" % (rc, out[-200:]))
        rc, out = s_client(srv.port, ["-tls1_2"])
        check("echo_12", rc == 0 and "hello" in out, "rc=%s out=%r" % (rc, out[-200:]))
        log = srv.log()
        check("sni_seen", "sni=localhost" in log and "TLSv1.3" in log and "TLSv1.2" in log, log)
        rc, out = s_client(srv.port, ["-CAfile", os.path.join(PKI, "otherca.pem")])
        check("wrong_ca_rejected_by_the_client", rc != 0 or "verify error" in out.lower(), "rc=%s out=%r" % (rc, out[-200:]))
        # raw garbage: each connection ends, and the next real client is still served
        vectors = {
            "http_request": b"GET / HTTP/1.1\r\n\r\n",
            "unknown_content_type": bytes.fromhex("630303000100"),
            "record_too_long": bytes.fromhex("16030348010000000000000000 0000".replace(" ", "")),
            "alert_of_one_byte": bytes.fromhex("150303000101"),
            "ccs_first": bytes.fromhex("140303000101"),
            "app_data_first": bytes.fromhex("170303000 1ff".replace(" ", "")),
            "hello_version_two": V7[:9] + b"\x02\x00" + V7[11:],
        }
        survived = 0
        for name, data in vectors.items():
            raw_send(srv.port, data)
            rc, out = s_client(srv.port, [])
            ok = srv.proc.poll() is None and rc == 0 and "hello" in out
            survived += 1 if ok else 0
            if not ok:
                print("FAIL malformed %s: the server did not survive (rc=%s)" % (name, rc))
        print("malformed: %d/%d survived" % (survived, len(vectors)))
        check("malformed", survived == len(vectors))
        reply = raw_send(srv.port, V7)
        check("server_hello_for_a_raw_hello", reply[:1] == b"\x16" and len(reply) > 5 and reply[5] == 2,
              "reply starts %r" % reply[:8])
    finally:
        srv.stop()

    srv = Server("mtls", "--client-ca", os.path.join(PKI, "ca.pem"))
    try:
        rc, out = s_client(srv.port, ["-cert", os.path.join(PKI, "client.pem"), "-key", os.path.join(PKI, "client.key")])
        check("mtls_ok", rc == 0 and "hello" in out, "rc=%s out=%r" % (rc, out[-200:]))
        rc, out = s_client(srv.port, [])
        log = srv.log()
        check("mtls_denied", "NO_PEER_CERT" in log and "client certificate sha256=" in log, log)
    finally:
        srv.stop()

    srv = Server("alpn", "--alpn", "h2,http/1.1")
    try:
        rc, out = s_client(srv.port, ["-alpn", "http/1.1,h2"], quiet=False)
        check("alpn_h2", "ALPN protocol: h2" in out, out[-300:])
    finally:
        srv.stop()
    failed = results.count(False)
    print("%d passed, %d failed" % (len(results) - failed, failed))
    return 1 if failed else 0


class Peer:
    """A TLS server in this process that behaves in one way per connection: `behave(conn)` gets the TLS socket."""

    def __init__(self, behave):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(PKI, "server.pem"), os.path.join(PKI, "server.key"))
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.stopping = False

        def run():
            while not self.stopping:
                try:
                    raw, _ = self.listener.accept()
                except OSError:
                    return
                try:
                    behave(ctx.wrap_socket(raw, server_side=True))
                except Exception:
                    pass

        threading.Thread(target=run, daemon=True).start()

    def stop(self):
        self.stopping = True
        self.listener.close()


def tlsc_run(port, extra, payload=b"hello\n", timeout=30):
    cmd = [TLSC, "--ca", os.path.join(PKI, "ca.pem")] + extra + ["localhost", str(port)]
    r = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")


def client_test():
    if not os.path.exists(TLSC):
        sys.stderr.write("build/tlsc is missing: run `c3c build tlsc` first\n")
        return 2
    subprocess.check_call(["bash", os.path.join(ROOT, "tests", "pki", "make-pki.sh")])
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print("%s %s%s" % ("ok  " if ok else "FAIL", name, "" if ok else ": " + detail))

    def slow(conn):
        conn.recv(4096)
        time.sleep(1.5)
        conn.sendall(b"late answer\n")
        conn.unwrap()

    def partial_then_drop(conn):
        conn.recv(4096)
        conn.sendall(b"partial")
        socket.socket(fileno=conn.detach()).close()  # no close_notify

    def silent(conn):
        conn.recv(4096)
        time.sleep(8)

    p = Peer(slow)
    rc, out, err = tlsc_run(p.port, [])
    check("late_answer_is_shown", rc == 0 and "late answer" in out, "rc=%s out=%r err=%r" % (rc, out, err))
    p.stop()

    p = Peer(partial_then_drop)
    rc, out, err = tlsc_run(p.port, [])
    check("truncated_session_is_a_failure", rc == 1 and "partial" in out and "TRUNCATED" in err, "rc=%s out=%r err=%r" % (rc, out, err))
    p.stop()

    p = Peer(silent)
    started = time.time()
    rc, out, err = tlsc_run(p.port, ["--timeout", "2"])
    check("silence_ends_after_the_timeout", rc == 0 and time.time() - started < 7, "rc=%s err=%r" % (rc, err))
    p.stop()

    p = Peer(lambda conn: conn.close())
    for bad in ("abc", "0", "-3"):
        rc, out, err = tlsc_run(p.port, ["--timeout", bad])
        check("timeout_%s_is_a_usage_error" % bad, rc == 2 and "--timeout" in err and "usage:" not in err, "rc=%s err=%r" % (rc, err))
    pin = hashlib_pin("server")
    rc, out, err = tlsc_run(p.port, ["--insecure", "--pin-sha256", pin])
    check("insecure_with_a_pin_says_pinned", "verify: pinned (chain not checked)" in out or "SKIPPED" not in out,
          "rc=%s out=%r" % (rc, out))
    p.stop()
    failed = results.count(False)
    print("%d passed, %d failed" % (len(results) - failed, failed))
    return 1 if failed else 0


def hashlib_pin(name):
    import hashlib
    with open(os.path.join(PKI, name + ".pem")) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        return serve(rest[0], int(rest[1]))
    if cmd == "serve-test":
        return serve_test()
    if cmd == "client-test":
        return client_test()
    names = []
    command = None
    if "--" in rest:
        i = rest.index("--")
        command = rest[i + 1:]
        rest = rest[:i]
    i = 0
    while i < len(rest):
        if rest[i] == "--scenario":
            i += 1
            while i < len(rest) and not rest[i].startswith("--"):
                names.append(rest[i])
                i += 1
        else:
            sys.stderr.write("unknown argument " + rest[i] + "\n")
            return 2
    for n in names:
        if n not in SCENARIOS and n not in PYTHON_PEERS:
            sys.stderr.write("unknown scenario %s (have: %s)\n" % (n, " ".join(sorted(SCENARIOS))))
            return 2
    names = names or DEFAULT
    if cmd == "start":
        start(names)
        return 0
    if cmd == "stop":
        stop()
        return 0
    if cmd == "run":
        if not command:
            sys.stderr.write("run needs a command after --\n")
            return 2
        try:
            start(names)
            return subprocess.call(command, cwd=ROOT)
        finally:
            stop()
    sys.stderr.write("unknown command " + cmd + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
