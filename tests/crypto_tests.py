import os
import sys
import random
import math
import numpy as np
from collections import deque

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna


BASE_TO_INT = {"A":0,"T":1,"C":2,"G":3}


# ------------------------------------------------
# BASIC UTILITIES
# ------------------------------------------------

def dna_to_bits(dna):

    bits=[]

    for b in dna:
        v=BASE_TO_INT[b]
        bits.append((v>>1)&1)
        bits.append(v&1)

    return bits


def dna_to_ints(dna):

    return [BASE_TO_INT[b] for b in dna]


def random_message():

    return os.urandom(32).hex()


# ------------------------------------------------
# RANDOMNESS METRICS
# ------------------------------------------------

def entropy(bits):

    p=sum(bits)/len(bits)

    if p==0 or p==1:
        return 0

    return -(p*math.log2(p)+(1-p)*math.log2(1-p))


def chi_square(bits):

    ones=sum(bits)
    zeros=len(bits)-ones

    expected=len(bits)/2

    return ((zeros-expected)**2+(ones-expected)**2)/expected


def serial_corr(bits):

    n=len(bits)

    mean=sum(bits)/n

    num=sum((bits[i]-mean)*(bits[i+1]-mean) for i in range(n-1))

    den=sum((b-mean)**2 for b in bits)

    if den==0:
        return 0

    return num/den


# ------------------------------------------------
# NPCR + UACI
# ------------------------------------------------

def npcr_uaci(c1,c2):

    a=dna_to_ints(c1)
    b=dna_to_ints(c2)

    n=len(a)

    changed=sum(1 for i in range(n) if a[i]!=b[i])

    npcr=changed/n

    uaci=sum(abs(a[i]-b[i]) for i in range(n))/(3*n)

    return npcr,uaci


# ------------------------------------------------
# VISUAL BARS
# ------------------------------------------------

def bar(value,width=28):

    filled=int(value*width)

    return "█"*filled+"░"*(width-filled)


def round_panel(title,values):

    lines=[]

    for i,v in enumerate(values):

        lines.append(f"R{i+1:02d} {bar(v)} {v:.3f}")

    return Panel("\n".join(lines),title=title)


# ------------------------------------------------
# AVALANCHE GRAPH
# ------------------------------------------------

def avalanche_graph(history):

    width=60

    lines=[]

    for v in history:

        pos=int(v*width)

        line="."*pos+"█"+"."*(width-pos)

        lines.append(line)

    return Panel("\n".join(lines[-20:]),title="Avalanche Convergence")


# ------------------------------------------------
# ROUND DIFFUSION
# ------------------------------------------------

def round_avalanche(cipher,dna):

    trace1=cipher.encrypt_with_trace(dna)

    bits=dna_to_bits(dna)

    flip=random.randint(0,len(bits)-1)
    bits[flip]^=1

    dna2="".join(["ATCG"[(bits[i]<<1)|bits[i+1]] for i in range(0,len(bits),2)])

    trace2=cipher.encrypt_with_trace(dna2)

    res=[]

    for r in range(len(trace1)):

        b1=dna_to_bits(trace1[r])
        b2=dna_to_bits(trace2[r])

        diff=sum(x^y for x,y in zip(b1,b2))

        res.append(diff/len(b1))

    return res


# ------------------------------------------------
# ROUND ENTROPY
# ------------------------------------------------

def round_entropy(cipher,dna):

    trace=cipher.encrypt_with_trace(dna)

    return [entropy(dna_to_bits(x)) for x in trace]


# ------------------------------------------------
# LAT ANALYZER
# ------------------------------------------------

def compute_lat():

    sbox=[6,4,12,5,0,7,2,14,1,15,3,13,8,10,9,11]

    size=len(sbox)

    lat=np.zeros((size,size))

    for a in range(size):

        for b in range(size):

            bias=0

            for x in range(size):

                ip=bin(a & x).count("1")%2
                op=bin(b & sbox[x]).count("1")%2

                if ip==op:
                    bias+=1
                else:
                    bias-=1

            lat[a][b]=bias

    return lat


def lat_table(lat):

    table=Table(title="LAT Bias")

    for i in range(8):
        table.add_column(str(i))

    for i in range(8):

        row=[str(int(lat[i][j])) for j in range(8)]

        table.add_row(*row)

    return Panel(table)


# ------------------------------------------------
# MAIN TEST SUITE
# ------------------------------------------------

def run_suite():

    trials=5000

    cipher=GCRC("test-key")
    cipher2=GCRC("test-keY")

    avalanche=[]
    key_avalanche=[]
    linear_matches=0

    all_bits=[]
    npcr_vals=[]
    uaci_vals=[]

    avalanche_hist=deque(maxlen=200)

    # precompute LAT
    lat=compute_lat()

    # initialize round metrics (fix for unbound warnings)

    rd=[]
    re=[]

    rd_samples=[]
    re_samples=[]

    # layout

    layout=Layout()

    layout.split_column(
        Layout(name="progress",size=3),
        Layout(name="row1"),
        Layout(name="row2"),
        Layout(name="row3")
    )

    layout["row1"].split_row(
        Layout(name="metrics"),
        Layout(name="lat")
    )

    layout["row2"].split_row(
        Layout(name="diffusion"),
        Layout(name="entropy")
    )

    layout["row3"].update(Panel("Starting tests..."))

    progress=Progress(
        TextColumn("[bold cyan]Running Tests"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn()
    )

    task=progress.add_task("tests",total=trials)

    with Live(layout,refresh_per_second=4):

        for i in range(trials):

            msg=random_message()

            dna=text_to_dna(msg)

            ct1=cipher.encrypt(dna)

            bits=dna_to_bits(dna)

            flip=random.randint(0,len(bits)-1)
            bits[flip]^=1

            dna2="".join(["ATCG"[(bits[i]<<1)|bits[i+1]] for i in range(0,len(bits),2)])

            ct2=cipher.encrypt(dna2)

            b1=dna_to_bits(ct1)
            b2=dna_to_bits(ct2)

            diff=[x^y for x,y in zip(b1,b2)]

            av=sum(diff)/len(diff)

            avalanche.append(av)
            avalanche_hist.append(av)

            ct_key=cipher2.encrypt(dna)

            b3=dna_to_bits(ct_key)

            key_diff=sum(x^y for x,y in zip(b1,b3))

            key_avalanche.append(key_diff/len(b1))

            lhs=b1[0]^b1[5]^b1[9]
            rhs=b2[3]^b2[7]^b2[12]

            if lhs==rhs:
                linear_matches+=1

            npcr,uaci=npcr_uaci(ct1,ct2)

            npcr_vals.append(npcr)
            uaci_vals.append(uaci)

            all_bits.extend(b1)

            # collect round metrics samples

            if len(rd_samples)<50:

                rd_samples.append(round_avalanche(cipher,dna))
                re_samples.append(round_entropy(cipher,dna))

                rd=np.mean(rd_samples,axis=0)
                re=np.mean(re_samples,axis=0)

            progress.advance(task)

            if (i+1)%100==0:

                stats={
                    "Avalanche":np.mean(avalanche),
                    "Key Avalanche":np.mean(key_avalanche),
                    "Entropy":entropy(all_bits),
                    "Bit Balance":sum(all_bits)/len(all_bits),
                    "ChiSquare":chi_square(all_bits),
                    "Serial Corr":serial_corr(all_bits),
                    "Linear Bias":abs((linear_matches/(i+1))-0.5),
                    "NPCR":np.mean(npcr_vals),
                    "UACI":np.mean(uaci_vals)
                }

                table=Table(title="Cipher Metrics")

                table.add_column("Metric")
                table.add_column("Value")

                for k,v in stats.items():
                    table.add_row(k,f"{v:.6f}")

                layout["progress"].update(Panel(progress))
                layout["metrics"].update(table)
                layout["lat"].update(lat_table(lat))
                layout["diffusion"].update(round_panel("Round Diffusion",rd))
                layout["entropy"].update(round_panel("Round Entropy",re))
                layout["row3"].update(avalanche_graph(avalanche_hist))


if __name__=="__main__":

    run_suite()