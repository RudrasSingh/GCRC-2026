from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt


def generate_keys():
    public_key, secret_key = generate_keypair()
    return public_key, secret_key


def encapsulate(public_key: bytes):
    ciphertext, shared_key = encrypt(public_key)
    return ciphertext, shared_key


def decapsulate(ciphertext, secret_key):
    shared_key = decrypt(secret_key, ciphertext)
    return shared_key