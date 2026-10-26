def xor_bytes(a: bytes, b: bytes, longest=False) -> bytes:
    return bytes((a[i] if len(a) > i else 0) ^ (b[i] if len(b) > i else 0) for i in range((min if not longest else max)(len(a), len(b))))


msg = b'\x00\x00\x00\x00\x00\x00\x00{"from":"alice","to":"bob","amount": "000010"}'
att = b'\x00\x00\x00\x00\x00\x00\x00{"from":"alice","to":"bob","amount": "000200"}'
jma = xor_bytes(msg, att)
print(msg.hex())
print(att.hex())
print(jma.hex())
pending_transaction = bytes.fromhex(input())
print(len(msg), len(pending_transaction))
print(xor_bytes(pending_transaction, jma, longest=True).hex())

