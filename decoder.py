import json
import hashlib
import hmac

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import dna_to_text
from pqc.kyber_mlkem import decapsulate


# ------------------------------------------------
# Load encrypted package
# ------------------------------------------------

def load_encrypted(filename="encrypted.json"):

    with open(filename, "r") as f:
        data = json.load(f)

    return data


# ------------------------------------------------
# Decrypt message
# ------------------------------------------------

def decrypt_message(data, secret_key):

    # recover Kyber ciphertext
    kem_cipher = bytes.fromhex(data["kyber_ciphertext"])

    # Kyber decapsulation
    shared_key = decapsulate(kem_cipher, secret_key)

    # verify integrity
    expected_hmac = data["hmac"]

    computed_hmac = hmac.new(
        shared_key,
        data["cipher_dna"].encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_hmac, computed_hmac):
        raise ValueError("Ciphertext integrity check failed!")

    # derive DNA cipher key
    dna_key = hashlib.sha256(shared_key).hexdigest()[:32]

    cipher = GCRC(dna_key)

    decrypted_dna = cipher.decrypt(data["cipher_dna"])

    decrypted_dna = decrypted_dna[:data["length"]]

    message = dna_to_text(decrypted_dna)

    return message


# ------------------------------------------------
# MAIN
# ------------------------------------------------

if __name__ == "__main__":

    print("\n=== DNA GCRC DECRYPTION ===\n")

    data = load_encrypted()

    with open("secret.key", "rb") as f:
        secret_key = f.read()

    message = decrypt_message(data, secret_key)

    print("\nRecovered message:")
    print(message)