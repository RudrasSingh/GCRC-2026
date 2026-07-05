from pqc.kyber_mlkem import generate_keys

pk, sk = generate_keys()

open("public.key", "wb").write(pk)
open("secret.key", "wb").write(sk)

print("Kyber keys generated.")