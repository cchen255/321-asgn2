#!/usr/bin/env python3


from diffie_hellman import DiffieHellman, aes_encrypt, aes_decrypt


def task_one():
    # public parameters
    q = 37
    a = 5
    demo_exchange(q, a)
    print('='*40)
    
    q_hex = ("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
            "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
            "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
            "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
            "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
            "DF1FB2BC2E4A4371")

    a_hex = ("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
             "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
             "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
             "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
             "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
             "855E6EEB22B3B2E5")
    
    # Convert hex to integers
    q = int(q_hex, 16)
    a = int(a_hex, 16)

    print('demo with BIG values')
    demo_exchange(q, a)

    print(f'========== MITM attack =============')
    demo_exchange_mitm(37, 5)


    print(f'========== MITM with a=1 =============, NOTE: shared secret is always 1') 
    print("When a=1, YA = 1^XA mod q = 1, YB = 1^XB mod q = 1")
    demo_exchange(37, 1)

    print(f'========== MITM with a=q ============= NOTE: shared secret is always 0')
    print("When a=q, YA = q^XA mod q = 0, YB = q^XB mod q = 0") 
    demo_exchange(37, 37)

    print(f'========== MITM with a=q-1 ============= NOTE: shared secret is always q-1, or 1')
    demo_exchange(37, 36)





def demo_exchange(q, a): 
    alice = DiffieHellman(q, a)
    bob = DiffieHellman(q, a)

    # alice generates keys
    alice_private = alice.generate_private_key()
    alice_public = alice.compute_public_key()

    # bob generates keys
    bob_private = bob.generate_private_key()
    bob_public = bob.compute_public_key()

    # make shared secrets
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)

    print(f'alice shared secret: {alice_shared}')
    print(f'bob shared secret: {bob_shared}')
    

    # create symmetric keys
    alice_key = alice.make_key()
    bob_key = bob.make_key()

    print(f'alice symmetric key: {alice_key}')
    print(f'bob symmetric key: {bob_key}')

    # send message

    # alice to bob
    alice_message = "Hi Bob!"
    alice_ciphertext = aes_encrypt(alice_key, alice_message)
    print(f"Alice encrypts '{alice_message}': {alice_ciphertext.hex()}")
    bob_decrypted = aes_decrypt(bob_key, alice_ciphertext)
    print(f"Bob decrypts:  '{bob_decrypted}'")
    
    # bob to alice
    bob_message = "Hi Alice!"
    bob_ciphertext = aes_encrypt(bob_key, bob_message)
    print(f"Bob encrypts '{bob_message}': {bob_ciphertext.hex()}")
    alice_decrypted = aes_decrypt(alice_key, bob_ciphertext)
    print(f"Alice decrypts:  '{alice_decrypted}'")


def demo_exchange_mitm(q, a): 
    alice = DiffieHellman(q, a)
    bob = DiffieHellman(q, a)
    mallory = DiffieHellman(q, a)

    # alice generates keys
    alice_private = alice.generate_private_key()
    alice_public = alice.compute_public_key()

    # bob generates keys
    bob_private = bob.generate_private_key()
    bob_public = bob.compute_public_key()

    # mallory generates private key
    mallory_private = mallory.generate_private_key()

    # make shared secrets
    alice_shared = alice.compute_shared_secret(q) # alice receives q instead of bob's public key
    bob_shared = bob.compute_shared_secret(q) # bob receives q instead of alice's public key
    mallory_shared = mallory.compute_shared_secret(q) # mallory can make shared secret also with q


    # create symmetric keys
    alice_key = alice.make_key()
    bob_key = bob.make_key()
    mallory_key = mallory.make_key()

    print(f'alice symmetric key: {alice_key}')
    print(f'bob symmetric key: {bob_key}')
    print(f'mallory symmetric key: {mallory_key}')

    # send message

    # alice to bob
    alice_message = "Hi Bob!"
    alice_ciphertext = aes_encrypt(alice_key, alice_message)
    print(f"Alice encrypts '{alice_message}': {alice_ciphertext.hex()}")
    bob_decrypted = aes_decrypt(bob_key, alice_ciphertext)
    print(f"Bob decrypts: '{bob_decrypted}'")
    
    # bob to alice
    bob_message = "Hi Alice!"
    bob_ciphertext = aes_encrypt(bob_key, bob_message)
    print(f"Bob encrypts '{bob_message}': {bob_ciphertext.hex()}")
    alice_decrypted = aes_decrypt(alice_key, bob_ciphertext)
    print(f"Alice decrypts:  '{alice_decrypted}'")



if __name__ == "__main__":
    task_one()
    