BASE_TO_INT = {"A":0,"T":1,"C":2,"G":3}
INT_TO_BASE = ["A","T","C","G"]

def dna_to_bits(dna):

    bits=[]

    for b in dna:
        v=BASE_TO_INT[b]
        bits.append((v>>1)&1)
        bits.append(v&1)

    return bits


def bits_to_dna(bits):

    dna=[]

    for i in range(0,len(bits),2):
        v=(bits[i]<<1)|bits[i+1]
        dna.append(INT_TO_BASE[v])

    return "".join(dna)


def dna_to_ints(dna):

    return [BASE_TO_INT[b] for b in dna]