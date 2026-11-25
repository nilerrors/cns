I made an even better hash function!

```python3
def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def bettererhash(msg):
    s = bytearray(msg.encode())

    for rnd in range(8):

        for i in range(len(s)):
            x = s[i]

            x = rol(x ^ ((rnd * 23 + i * 17) & 0xff),
                    ((rnd ^ i) & 7))

            x = (x + ((rnd + 1) * (i + 3))) & 0xff

            s[i] = x

        for i in range(1, len(s)):
            s[i] ^= rol(s[i - 1], i & 7)

    return s.hex()
```

`2647457a3b8ecb1cfedef2ce42958eeaa0016bb097c81b0948913d08e619a42e59f30e`
