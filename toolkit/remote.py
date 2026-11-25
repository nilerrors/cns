"""
remote.py -- tiny helpers for interactive / server-based challenges (key
distribution, oracles, login services). No pwntools needed; stdlib + requests.

    from remote import Tube, http_json
    t = Tube("cns-test.idlab.uantwerpen.be", 50011)
    t.recv_until(b"name:")
    t.sendline(b"saba")
    print(t.recv_all(timeout=1).decode())

    j = http_json("http://host:port/params")        # GET -> dict
    j = http_json("http://host:port/directory", post={"name":"x","y":123})
"""
import socket, time, sys


class Tube:
    """Minimal line-oriented TCP client (a stripped-down pwntools 'remote')."""

    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def recv_until(self, marker, echo=True):
        """Read until `marker` (bytes) appears; return everything up to & incl it."""
        if isinstance(marker, str):
            marker = marker.encode()
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(marker)
        cut = i + len(marker) if i >= 0 else len(self.buf)
        out, self.buf = self.buf[:cut], self.buf[cut:]
        if echo:
            sys.stdout.write(out.decode("latin-1"))
            sys.stdout.flush()
        return out

    def recv_line(self, echo=True):
        return self.recv_until(b"\n", echo)

    def recv_all(self, timeout=1.0, echo=True):
        """Drain whatever arrives within `timeout` seconds of silence."""
        self.sock.settimeout(timeout)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
        except socket.timeout:
            pass
        out, self.buf = self.buf, b""
        if echo:
            sys.stdout.write(out.decode("latin-1"))
            sys.stdout.flush()
        return out

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def interactive(self):
        """Hand control to the terminal (type to the socket, see replies)."""
        import threading
        def reader():
            try:
                while True:
                    d = self.sock.recv(4096)
                    if not d:
                        break
                    sys.stdout.write(d.decode("latin-1")); sys.stdout.flush()
            except OSError:
                pass
        threading.Thread(target=reader, daemon=True).start()
        try:
            for line in sys.stdin:
                self.send(line)
        except KeyboardInterrupt:
            pass

    def close(self):
        self.sock.close()


def http_json(url, post=None, params=None, timeout=15, **kw):
    """GET (or POST when `post` is given) a JSON endpoint -> parsed object.
    Needs `requests` (present in the lab venv)."""
    import requests
    if post is not None:
        r = requests.post(url, json=post, params=params, timeout=timeout, **kw)
    else:
        r = requests.get(url, params=params, timeout=timeout, **kw)
    r.raise_for_status()
    try:
        return r.json()
    except ValueError:
        return r.text
