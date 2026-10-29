import socket
import hashlib

host = "cns-test.idlab.uantwerpen.be"
port = 50006

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

def receive(s, write=True):
    BUFFER_SIZE = 1024
    buffer = ""
    while msg := s.recv(BUFFER_SIZE):
        buffer += msg.decode("ascii")
        if write:
            print(msg.decode("ascii"), end='')
        if len(msg) < BUFFER_SIZE:
            break
    return buffer


def send(s, msg):
    s.send(msg)
    s.send(b'\r\n')
    print(msg.decode("ascii"))

receive(s)

rcv = receive(s, False)
current_code = rcv.splitlines()[1].split('CURRENT CODE: ')[1]
print(current_code)

next_code = hashlib.sha256(bytes.fromhex(current_code)).hexdigest()
send(s, next_code.encode())

receive(s)

s.close()

