from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes
import base64
import json

if __name__ == '__main__':
    password = b'WeakP4asswd'

    key = scrypt(password, get_random_bytes(16), 16, N=2**14, r=8, p=1)
    print(key)