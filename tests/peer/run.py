#!/usr/bin/env python3
"""Starts and stops the test peers (openssl s_server) and publishes where they listen.

  python3 -I tests/peer/run.py start [--scenario NAME ...]   start peers, write tests/peer/out/state.txt, exit
  python3 -I tests/peer/run.py stop                          kill every recorded peer
  python3 -I tests/peer/run.py run [--scenario NAME ...] -- CMD ...   start, run CMD, stop (for CI)
  python3 -I tests/peer/run.py serve NAME PORT               (internal) run one python peer in the foreground

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


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        return serve(rest[0], int(rest[1]))
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
