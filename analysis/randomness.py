import math


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