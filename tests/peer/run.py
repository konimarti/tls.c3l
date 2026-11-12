#!/usr/bin/env python3
"""Starts and stops the test peers (openssl s_server) and publishes where they listen.

  python3 -I tests/peer/run.py start [--scenario NAME ...]   start peers, write tests/peer/out/state.txt, exit
  python3 -I tests/peer/run.py stop                          kill every recorded peer
  python3 -I tests/peer/run.py run [--scenario NAME ...] -- CMD ...   start, run CMD, stop (for CI)

The C3 tests read tests/peer/out/state.txt (KEY=value lines). Standard library only.
"""
import os
import shutil
import signal
import socket
import subprocess
import sys
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
DEFAULT = ["tls13", "tls12", "rsa13", "rsa12", "rev13", "ip", "trace13"]


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
    pids = []
    lines = ["CA=" + os.path.join(PKI, "ca.pem"), "DIR=" + PKI, "OUT=" + OUT]
    try:
        for name in names:
            cert, extra = SCENARIOS[name]
            port = free_port()
            log = open(os.path.join(OUT, name + ".log"), "wb")
            cmd = (["stdbuf", "-oL", "-eL"] if shutil.which("stdbuf") else []) + ["openssl", "s_server", "-quiet", "-accept", "127.0.0.1:%d" % port,
                   "-cert", os.path.join(PKI, cert + ".pem"), "-key", os.path.join(PKI, cert + ".key")] + extra
            proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
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


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
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
        if n not in SCENARIOS:
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
