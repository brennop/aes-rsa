# AES Encryption
#
# resources
# -
# http://www.moserware.com/assets/stick-figure-guide-to-advanced/A%20Stick%20Figure%20Guide%20to%20the%20Advanced%20Encryption%20Standard%20%28AES%29.pdf
# https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

from functools import reduce
from operator import xor

SBOX = b'c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\'\xb2u\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8ap>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16'

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

# funções auxiliares

# pkcs#7
# https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
def pad(message):
    size = 16 - len(message) % 16 # sempre haverá um padding
    return message + bytes([size] * size) # constroi um preenchimento de size sizes

def unpad(message):
    size = message[-1]  # tamanho do padding é o ultimo elemento
    return message[:-size] # retorna a mensagem sem o preenchimento

def rotate(list):
    return (list*2)[1:5]

def split(message, size):
    return [message[i:i+size] for i in range(0, len(message), size)]

def inc(bytes):
    as_int = int.from_bytes(bytes, "big")
    while True:
        as_int += 1
        yield (as_int).to_bytes(16, "big")

def xtime(x):
    return (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else (x << 1)

### Implementação

def expand_key(key):
    # 4 primeiras words
    words = split(key, 4)

    # 40 words restantes
    for i in range(4, 44):
        temp = words[i-1]
        if i % 4 == 0:
            *temp, = map(xor, (rotate(temp)).translate(SBOX), [RCON[i//4], 0, 0, 0])
        words.append(bytes([*map(xor, words[i-4], temp)]))

    return [b''.join(word) for word in split(words, 4)]

def add_round_key(state, key):
    return bytes(map(xor, state, key))

def sub_bytes(state):
    return state.translate(SBOX)

def shift_rows(state, offset = 5):
    return (state * offset)[::offset]

def mix_column(r):
    return [reduce(xor, [a, *r, xtime(a^b)]) for a,b in zip(r,rotate(r))]

def mix_columns(state):
    return [x for r in split(state, 4) for x in mix_column(r)]

def cipher(block, keys):
    # Sec. 5.1.4
    state = add_round_key(block, keys[0])

    for round in range(1, 11):
        state = sub_bytes(state)    # Sec. 5.1.1
        state = shift_rows(state)   # Sec 5.1.2
        if round != 10:
            state = mix_columns(state)  # Sec 5.1.3
        state = add_round_key(state, keys[round])

    return state

def ctr(message, key, iv):
    keys = expand_key(key)

    blocks = split(message, 16)
    ciphers = (cipher(nonce, keys) for nonce in inc(iv))

    cipher_text = map(add_round_key, blocks, ciphers)

    return b''.join(map(bytes, cipher_text))

