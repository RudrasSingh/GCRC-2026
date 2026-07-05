import json
import hashlib
import hmac

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna
from pqc.kyber_mlkem import encapsulate


# ------------------------------------------------
# Encrypt message
# ------------------------------------------------

def encrypt_message(message: str, public_key: bytes):

    # Kyber encapsulation
    kem_ciphertext, shared_key = encapsulate(public_key)

    # derive DNA cipher key
    dna_key = hashlib.sha256(shared_key).hexdigest()[:32]

    cipher = GCRC(dna_key)

    # convert text → DNA
    dna = text_to_dna(message)

    encrypted_dna = cipher.encrypt(dna)

    # create integrity tag
    hmac_tag = hmac.new(
        shared_key,
        encrypted_dna.encode(),
        hashlib.sha256
    ).hexdigest()

    data = {
        "cipher_dna": encrypted_dna,
        "kyber_ciphertext": kem_ciphertext.hex(),
        "hmac": hmac_tag,
        "length": len(dna)
    }

    return data


# ------------------------------------------------
# Save encrypted file
# ------------------------------------------------

def save_encrypted(data, filename="encrypted.json"):

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print("\nEncryption saved to:", filename)


# ------------------------------------------------
# MAIN
# ------------------------------------------------

if __name__ == "__main__":

    print("\n=== DNA GCRC ENCRYPTION ===\n")

    message = input("Enter message: ")

    # load Kyber public key
    with open("public.key", "rb") as f:
        public_key = f.read()

    encrypted_data = encrypt_message(message, public_key)

    print("\nEncrypted DNA:")
    print(encrypted_data["cipher_dna"])

    save_encrypted(encrypted_data)