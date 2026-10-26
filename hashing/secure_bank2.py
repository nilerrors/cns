import socket
import json
import datetime
import time
import hashlib

host = "cns-test.idlab.uantwerpen.be"
port = 50003

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

def receive(s):
    BUFFER_SIZE = 1024
    while msg := s.recv(BUFFER_SIZE):
        print(msg.decode("ascii"), end='')
        if len(msg) < BUFFER_SIZE:
            break

def canonicalize(payment):
    return json.dumps(
        payment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def send(s, msg):
    s.send(msg)
    s.send(b'\r\n')
    print(msg.decode("ascii"))

receive(s)


# timestamp must be in last minute
# -3 (instead of -1) because for some reason my pc clock is 2 minutes forward
DELTA_MINUTES = 3

#'2026-10-19t14:03:23.764927+00:00'
timestamp = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=DELTA_MINUTES)).isoformat()

# immutable base data used for both payment payloads
def make_payment(to_account):
    return canonicalize({
        "amount": 10,
        "currency": "EUR",
        "from_account": "SIM-a",
        "reference": "ref",
        "timestamp": timestamp,
        "to_account": f"SIM-{to_account}"
    })


def truncate_hash(payment):
    TRUNCATE_BYTES = 4  # because fingertip is 8hex chars -> 4bytes
    return hashlib.sha256(payment).digest()[:TRUNCATE_BYTES]

seen = {}
i = 0
while True:
    d = truncate_hash(make_payment(i))
    if d in seen:
        print(i, seen[d])
        send(s, make_payment(i))
        receive(s)
        send(s, make_payment(seen[d]))
        receive(s)
        break
    seen[d] = i
    i += 1


# send(s, make_payment('b'))
# receive(s)
# send(s, make_payment('c'))
# receive(s)

s.close()

