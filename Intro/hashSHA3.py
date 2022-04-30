from Cryptodome.Hash import SHA3_256
import base64

if __name__ == '__main__':
    hash_generator = SHA3_256.new()

    with open(__file__, "rb") as f_input:
        hash_generator.update(f_input.read().encode())

    print(hash_generator.hexdigest())