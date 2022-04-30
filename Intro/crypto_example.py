from pydoc import plain
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

if __name__ == '__main__':

    IV = get_random_bytes(AES.block_size)

    key = get_random_bytes(AES.key_size[2])

    plaintex = b'These are the data to encrypt !!'

    print(len(plaintex))

    cipher_enc = AES.new(key, AES.MODE_CBC, IV)

    cipthertext = cipher_enc.encrypt(plaintex)
    print(cipthertext)

    cipher_dec = AES.new(key, AES.MODE_CBC, IV)
    decrypted_data = cipher_dec.decrypt(cipthertext)
    print(decrypted_data)

    plaintext = b'Unaligned string...'

    cipher_enc = AES.new(key, AES.MODE_CBC, IV)
    padded_data = pad(plaintext, AES.block_size)
    print(padded_data)

    cipthertext = cipher_enc.encrypt(padded_data)
    print(cipthertext)

    cipher_dec = AES.new(key, AES.MODE_CBC, IV)
    decrypted_data = cipher_dec.decrypt(cipthertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    print(unpadded_data)