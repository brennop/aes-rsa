from random import randrange
from os import urandom
from math import ceil
from hashlib import sha1
from operator import xor

## TODO: providenciar a propria implementacao
## TODO: acelerar essa operacao
def miller_rabin(n):
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(40):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def rand_odd(nbits=1024):
    return randrange(2 ** (nbits - 2), 2 ** (nbits - 1)) * 2 - 1

## TODO: benchmark vs sem iterador
def gen_prime():
    return next(filter(miller_rabin, iter(rand_odd, 0)))

# https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1
def mask(data, seed, mlen):
    t = b''
    for counter in range(ceil(mlen / 20)):
        c = counter.to_bytes(4, "big")
        t += sha1(seed + c).digest()
    return bytes(map(xor, data, bytes(len(data)) + t[:mlen]))


def gen_keys():
    p = gen_prime()
    q = gen_prime()

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    d = pow(e, -1, phi_n)

    public_key = (n, e)
    private_key = (n, d)

    return (public_key, private_key)


# https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
#
# RSAES-OAEP-ENCRYPT ((n, e), M, L)
def oaep_encrypt(public_key, message):
    # TODO: length checking

    n, e = public_key

    # k denotes the length in octets of the RSA modulus n
    k = (n.bit_length() + 7) // 8
    message_len = len(message)

    hash_len = 20
    lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"

    padding_string = b"\x00" * (k - message_len - 2 * hash_len - 2)

    data_block = lable_hash + padding_string + b'\x01' + message

    seed = urandom(hash_len) 

    masked_data_block = mask(data_block, seed, k - hash_len - 1)
    masked_seed = mask(seed, masked_data_block, hash_len)

    encoded_message =  b'\x00' + masked_seed + masked_data_block

    m = int.from_bytes(encoded_message, "big")
    c = pow(m, e, n)
    return c.to_bytes(k, "big")


# https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.2
# 
# RSAES-OAEP-DECRYPT (K, C, L)
def oaep_decrypt(private_key, ciphertext):
    # TODO: length checking

    (n, d) = private_key

    k = (n.bit_length() + 7) // 8
    c = int.from_bytes(ciphertext, "big")

    m = pow(c, d, n)

    em = m.to_bytes(k, "big")

    # decoding

    hash_len = 20
    # lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"

    _, masked_seed, masked_data_block = em[:1], em[1:1+hash_len], em[1 + hash_len:]

    seed = mask(masked_seed, masked_data_block, hash_len)
    data_block = mask(masked_data_block, seed, k - hash_len - 1)

    _, message = data_block.split(b'\x01')

    return message

