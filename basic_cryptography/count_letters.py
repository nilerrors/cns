#qnb{vsi-fihczlnb-dlyi-vsi-fibv-plaahib-fi-zv-l-hzici-plaahi-mr-l-frtbbihb-plaahi}

class FreqAttackWords:
    def __init__(self, words: list[str], crib: tuple[str, str]):
        self.words = words
        self.crib = crib

    def decrypt(self, msg: str) -> str:
        changed = [False for _ in msg]
        old_count = -1
        count = sum(changed)
        while old_count != count:
            old_count = count
            old_msg = msg
            msg = ""
            for i, c in enumerate(old_msg):
                found = False
                if not changed[i]:
                    for cc in self.crib[0]:
                        if c == cc:
                            found = True
                            changed[i] = True
                            msg += self.crib[1][self.crib[0].find(cc)]
                            break
                if not found:
                    msg += c
            count = sum(changed)
        return msg


attack = FreqAttackWords(open("wordlist.txt", "r").readlines(), ("vsqnbfdlyihtczapm", "thcnsbmakelugifwo"))
print(attack.decrypt("qnb{vsi-fihczlnb-dlyi-vsi-fibv-plaahib-fi-zv-l-hzici-plaahi-mr-l-frtbbihb-plaahi}"))

