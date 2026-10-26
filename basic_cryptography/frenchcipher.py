import string

class Vigenere:
    def __init__(self, key):
        self.key = [ord(c) - ord('a') for c in key]
        self._i = 0

    def by(self):
        self._i += 1
        return self.key[(self._i - 1) % len(self.key)]

    def shift(self, c: str, shift_right=True) -> str:
        if c not in string.ascii_lowercase:
            return c
        start = ord('a')
        cord = ord(c)

        return chr(start + (cord - start + (1 if shift_right else -1) * self.by()) % 26)

    def encrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, shift_right=True) for c in msg])

    def decrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, shift_right=False) for c in msg])


vig = Vigenere("croissant")
print(vig.decrypt(input()))

