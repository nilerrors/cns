import socket
import time

host = "cns-test.idlab.uantwerpen.be"
port = 50006


def read_chunk(s, timeout=12):
    s.settimeout(timeout)
    data = b""
    try:
        while chunk := s.recv(1024):
            data += chunk
            if len(chunk) < 1024:
                break
    except socket.timeout:
        pass
    return data.decode("ascii", errors="replace")


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t_connect = time.time()
s.connect((host, port))
local_addr = s.getsockname()
print("local address/port:", local_addr, "connect time:", t_connect)

banner = read_chunk(s)
print("BANNER + first code at", time.time())
print(repr(banner))

for i in range(8):
    msg = read_chunk(s)
    print(f"\nPUSH {i} at t={time.time():.3f}")
    print(repr(msg))

s.close()



# import socket
# import hashlib
#
# host = "cns-test.idlab.uantwerpen.be"
# port = 50006
#
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((host, port))
#
# def receive(s, write=True):
#     BUFFER_SIZE = 1024
#     buffer = ""
#     while msg := s.recv(BUFFER_SIZE):
#         buffer += msg.decode("ascii")
#         if write:
#             print(msg.decode("ascii"), end='')
#         if len(msg) < BUFFER_SIZE:
#             break
#     return buffer
#
#
# def send(s, msg):
#     s.send(msg)
#     s.send(b'\r\n')
#     print(msg.decode("ascii"))
#
# receive(s)
#
# all_codes = ['4c97b6e9ee431368f78934699f9c122b28ebf39222a756ca9125db4085f889de', 'c344328ac6c07e23384914be2eed3d7308a1600cdd9106286be101b6735486f6', '21929c709a4a882cf310bf693ee29bd96d32c9d547c56b009cf1e1867090f1da', 'ec2cb3024fa39378d985ffa14140c0ce8de37bd0c6efde776c754f372153c11f', '231c3c50d2e5c875dfaea58242818c267a178ce0bb8560a8c6386c9455964f86']
#
# # rcv_codes_n = 5
# # all_codes = []
# # while True:
# #     rcv = receive(s, False)
# #     current_code = rcv.splitlines()[1].split('CURRENT CODE: ')[1]
# #     all_codes.append(current_code)
# #     print(current_code)
# #     if len(all_codes) >= rcv_codes_n:
# #         break
#
# print(all_codes)
#
# # guess next code
# # next_code = 
#
# s.close()

