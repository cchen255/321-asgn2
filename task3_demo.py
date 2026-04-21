#!/usr/bin/env python3

from rsa import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def int_to_bytes(x):
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def derive_key_from_secret(secret_int):
    # truncate SHA256 to 16 bytes for AES-128
    return hashlib.sha256(int_to_bytes(secret_int)).digest()[:16]

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def task3_part2(rsa):
    print('=' * 20 + ' Task 3 Part 2: RSA malleability attack ' + '=' * 20)

    # Alice's public key
    n, e = rsa.public_key
    _, d = rsa.private_key

    # Bob chooses a secret s in Z*_n
    s = secrets.randbelow(n - 2) + 1
    while number.GCD(s, n) != 1:
        s = secrets.randbelow(n - 2) + 1

    print(f"Bob's original secret s: {s}")

    # Bob encrypts s with Alice's public key
    c = rsa.encrypt(s)
    print(f"Bob sends ciphertext c: {c}")

    # Mallory chooses multiplier r
    r = 2
    while number.GCD(r, n) != 1:
        r += 1

    # Mallory computes c' = c * r^e mod n
    c_prime = (c * pow(r, e, n)) % n
    print(f"Mallory replaces c with c': {c_prime}")

    # Alice decrypts c'
    s_prime = rsa.decrypt(c_prime)
    print(f"Alice decrypts c' and gets s': {s_prime}")

    # Alice derives AES key from s' and encrypts a message
    alice_key = derive_key_from_secret(s_prime)
    message = "Hi Bob!"
    iv, c0 = aes_encrypt(alice_key, message)

    print(f"Alice's AES ciphertext c0: {c0.hex()}")

    # Mallory computes r^-1 mod n
    r_inverse = rsa.mod_inverse(r, n)

    # Recover original s from s' = s*r mod n
    recovered_s = (s_prime * r_inverse) % n
    print(f"Mallory recovers original s: {recovered_s}")

    # Mallory now computes the same s' Alice used
    recovered_s_prime = (recovered_s * r) % n

    # Derive same AES key and decrypt message
    mallory_key = derive_key_from_secret(recovered_s_prime)
    recovered_message = aes_decrypt(mallory_key, iv, c0)

    print(f"Mallory decrypts c0 and recovers message: '{recovered_message}'")
    print()


def demo_rsa(rsa):    
    # string message
    message_str = "Hello World!"
    print(f"Original message (string): '{message_str}'")
    
    # Show conversion process
    message_as_int = rsa.string_to_int(message_str)
    print(f"String as bytes: {message_str.encode('utf-8')}")
    print(f"Bytes as hex: {message_str.encode('utf-8').hex()}")
    print(f"Hex as integer: {message_as_int}")
    print()
    
    ciphertext_str = rsa.encrypt_string(message_str)
    print(f"Encrypted ciphertext: {ciphertext_str}")
    
    decrypted_str = rsa.decrypt_string(ciphertext_str)
    print(f"Decrypted message: '{decrypted_str}'")
    print()

def task_three():
    rsa = RSA(2048)

    print('='*20 + 'RSA encryption-decryption demo' + '='*20)
    # generate key pair
    rsa.generate_keypair()

    # encrypt and decrypt
    demo_rsa(rsa)
    task3_part2(rsa)
        

if __name__ == "__main__":
    task_three()
